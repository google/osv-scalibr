// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package analyzer provides advanced security analysis capabilities for OSV-SCALIBR.
package analyzer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
)

// SecurityLevel represents the severity of a security finding.
type SecurityLevel int

const (
	SecurityLevelInfo SecurityLevel = iota
	SecurityLevelLow
	SecurityLevelMedium
	SecurityLevelHigh
	SecurityLevelCritical
)

// SecurityFinding represents a security issue found during analysis.
type SecurityFinding struct {
	ID          string
	Title       string
	Description string
	Level       SecurityLevel
	Category    string
	Location    string
	Evidence    string
	Remediation string
	References  []string
}

// SecurityRule defines a security check to perform.
type SecurityRule struct {
	ID          string
	Name        string
	Description string
	Category    string
	Level       SecurityLevel
	Patterns    []*regexp.Regexp
	FileTypes   []string
	Checker     func(content, filePath string) []SecurityFinding
}

// Config configures the security analyzer.
type Config struct {
	EnabledCategories    []string
	MaxConcurrentChecks  int
	EnableHeuristics     bool
	EnableDeepAnalysis   bool
	CustomRules          []*SecurityRule
	ExcludePatterns      []string
	MaxFileSizeBytes     int64
}

// DefaultConfig returns a secure default configuration.
func DefaultConfig() Config {
	return Config{
		EnabledCategories: []string{
			"credentials", "crypto", "injection", "path-traversal",
			"insecure-random", "hardcoded-secrets", "weak-crypto",
		},
		MaxConcurrentChecks: 8,
		EnableHeuristics:    true,
		EnableDeepAnalysis:  true,
		MaxFileSizeBytes:    50 * 1024 * 1024, // 50MB
		ExcludePatterns: []string{
			"*/test/*", "*/tests/*", "*_test.go", "*.test.js",
			"*/node_modules/*", "*/vendor/*", "*/.git/*",
		},
	}
}

// Analyzer performs advanced security analysis on extracted packages and files.
type Analyzer struct {
	config    Config
	rules     map[string]*SecurityRule
	cache     sync.Map
	semaphore chan struct{}
}

// New creates a new security analyzer.
func New(cfg Config) *Analyzer {
	a := &Analyzer{
		config:    cfg,
		rules:     make(map[string]*SecurityRule),
		semaphore: make(chan struct{}, cfg.MaxConcurrentChecks),
	}
	
	a.registerBuiltinRules()
	a.registerCustomRules(cfg.CustomRules)
	
	return a
}

// AnalyzeInventory performs security analysis on an inventory.
func (a *Analyzer) AnalyzeInventory(ctx context.Context, inv *inventory.Inventory) ([]SecurityFinding, error) {
	var findings []SecurityFinding
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Analyze packages for known vulnerabilities and suspicious patterns
	for _, pkg := range inv.Packages {
		wg.Add(1)
		go func(pkg *extractor.Package) {
			defer wg.Done()
			
			select {
			case a.semaphore <- struct{}{}:
				defer func() { <-a.semaphore }()
			case <-ctx.Done():
				return
			}
			
			pkgFindings := a.analyzePackage(pkg)
			
			mu.Lock()
			findings = append(findings, pkgFindings...)
			mu.Unlock()
		}(pkg)
	}
	
	wg.Wait()
	
	return findings, nil
}

// AnalyzeFile performs security analysis on a single file.
func (a *Analyzer) AnalyzeFile(ctx context.Context, filePath, content string) ([]SecurityFinding, error) {
	if a.shouldExcludeFile(filePath) {
		return nil, nil
	}
	
	// Check cache
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	cacheKey := filePath + ":" + hash
	
	if cached, ok := a.cache.Load(cacheKey); ok {
		if findings, ok := cached.([]SecurityFinding); ok {
			return findings, nil
		}
	}
	
	var findings []SecurityFinding
	
	// Apply all relevant security rules
	for _, rule := range a.rules {
		if !a.isCategoryEnabled(rule.Category) {
			continue
		}
		
		if !a.matchesFileType(filePath, rule.FileTypes) {
			continue
		}
		
		// Pattern-based checks
		for _, pattern := range rule.Patterns {
			matches := pattern.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				finding := SecurityFinding{
					ID:          rule.ID,
					Title:       rule.Name,
					Description: rule.Description,
					Level:       rule.Level,
					Category:    rule.Category,
					Location:    filePath,
					Evidence:    strings.Join(match, " "),
					Remediation: a.getRemediation(rule.ID),
					References:  a.getReferences(rule.ID),
				}
				findings = append(findings, finding)
			}
		}
		
		// Custom checker function
		if rule.Checker != nil {
			customFindings := rule.Checker(content, filePath)
			findings = append(findings, customFindings...)
		}
	}
	
	// Cache results
	a.cache.Store(cacheKey, findings)
	
	return findings, nil
}

// analyzePackage performs security analysis on a package.
func (a *Analyzer) analyzePackage(pkg *extractor.Package) []SecurityFinding {
	var findings []SecurityFinding
	
	// Check for suspicious package names
	if a.isSuspiciousPackageName(pkg.Name) {
		findings = append(findings, SecurityFinding{
			ID:          "SUSP_PKG_NAME",
			Title:       "Suspicious Package Name",
			Description: "Package name contains suspicious patterns that may indicate typosquatting",
			Level:       SecurityLevelMedium,
			Category:    "supply-chain",
			Location:    strings.Join(pkg.Locations, ", "),
			Evidence:    pkg.Name,
			Remediation: "Verify the package name is correct and from a trusted source",
		})
	}
	
	// Check for development/test packages in production
	if a.isDevelopmentPackage(pkg.Name) {
		findings = append(findings, SecurityFinding{
			ID:          "DEV_PKG_PROD",
			Title:       "Development Package in Production",
			Description: "Development or test package detected in production dependencies",
			Level:       SecurityLevelLow,
			Category:    "configuration",
			Location:    strings.Join(pkg.Locations, ", "),
			Evidence:    pkg.Name,
			Remediation: "Remove development dependencies from production builds",
		})
	}
	
	// Check for outdated packages (if version info available)
	if pkg.Version != "" && a.isOutdatedVersion(pkg.Name, pkg.Version) {
		findings = append(findings, SecurityFinding{
			ID:          "OUTDATED_PKG",
			Title:       "Outdated Package Version",
			Description: "Package version is significantly outdated and may contain known vulnerabilities",
			Level:       SecurityLevelMedium,
			Category:    "vulnerability",
			Location:    strings.Join(pkg.Locations, ", "),
			Evidence:    fmt.Sprintf("%s@%s", pkg.Name, pkg.Version),
			Remediation: "Update to the latest stable version",
		})
	}
	
	return findings
}

// registerBuiltinRules registers the built-in security rules.
func (a *Analyzer) registerBuiltinRules() {
	// Hardcoded credentials
	a.rules["HARDCODED_PASSWORD"] = &SecurityRule{
		ID:          "HARDCODED_PASSWORD",
		Name:        "Hardcoded Password",
		Description: "Hardcoded password found in source code",
		Category:    "credentials",
		Level:       SecurityLevelHigh,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)password\s*[:=]\s*["'][^"']{8,}["']`),
			regexp.MustCompile(`(?i)passwd\s*[:=]\s*["'][^"']{8,}["']`),
			regexp.MustCompile(`(?i)pwd\s*[:=]\s*["'][^"']{8,}["']`),
		},
		FileTypes: []string{".go", ".java", ".py", ".js", ".ts", ".rb", ".php"},
	}
	
	// API Keys
	a.rules["HARDCODED_API_KEY"] = &SecurityRule{
		ID:          "HARDCODED_API_KEY",
		Name:        "Hardcoded API Key",
		Description: "Hardcoded API key found in source code",
		Category:    "credentials",
		Level:       SecurityLevelCritical,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*["'][A-Za-z0-9]{20,}["']`),
			regexp.MustCompile(`(?i)secret[_-]?key\s*[:=]\s*["'][A-Za-z0-9]{20,}["']`),
			regexp.MustCompile(`(?i)access[_-]?token\s*[:=]\s*["'][A-Za-z0-9]{20,}["']`),
		},
		FileTypes: []string{".go", ".java", ".py", ".js", ".ts", ".rb", ".php", ".yml", ".yaml", ".json"},
	}
	
	// SQL Injection
	a.rules["SQL_INJECTION"] = &SecurityRule{
		ID:          "SQL_INJECTION",
		Name:        "Potential SQL Injection",
		Description: "Code pattern that may be vulnerable to SQL injection",
		Category:    "injection",
		Level:       SecurityLevelHigh,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)query\s*\+\s*["']`),
			regexp.MustCompile(`(?i)["']\s*\+\s*\w+\s*\+\s*["']`),
			regexp.MustCompile(`(?i)execute\s*\(\s*["'][^"']*["']\s*\+`),
		},
		FileTypes: []string{".go", ".java", ".py", ".js", ".ts", ".rb", ".php"},
	}
	
	// Command Injection
	a.rules["COMMAND_INJECTION"] = &SecurityRule{
		ID:          "COMMAND_INJECTION",
		Name:        "Potential Command Injection",
		Description: "Code pattern that may be vulnerable to command injection",
		Category:    "injection",
		Level:       SecurityLevelHigh,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)exec\s*\(\s*["'][^"']*["']\s*\+`),
			regexp.MustCompile(`(?i)system\s*\(\s*["'][^"']*["']\s*\+`),
			regexp.MustCompile(`(?i)os\.system\s*\(`),
		},
		FileTypes: []string{".go", ".java", ".py", ".js", ".ts", ".rb", ".php"},
	}
	
	// Path Traversal
	a.rules["PATH_TRAVERSAL"] = &SecurityRule{
		ID:          "PATH_TRAVERSAL",
		Name:        "Potential Path Traversal",
		Description: "Code pattern that may be vulnerable to path traversal attacks",
		Category:    "path-traversal",
		Level:       SecurityLevelMedium,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`\.\./`),
			regexp.MustCompile(`\.\.\\`),
			regexp.MustCompile(`(?i)filepath\.join\s*\([^)]*\.\.[^)]*\)`),
		},
		FileTypes: []string{".go", ".java", ".py", ".js", ".ts", ".rb", ".php"},
	}
	
	// Weak Cryptography
	a.rules["WEAK_CRYPTO"] = &SecurityRule{
		ID:          "WEAK_CRYPTO",
		Name:        "Weak Cryptographic Algorithm",
		Description: "Use of weak or deprecated cryptographic algorithms",
		Category:    "crypto",
		Level:       SecurityLevelMedium,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)md5`),
			regexp.MustCompile(`(?i)sha1`),
			regexp.MustCompile(`(?i)des`),
			regexp.MustCompile(`(?i)rc4`),
		},
		FileTypes: []string{".go", ".java", ".py", ".js", ".ts", ".rb", ".php"},
	}
	
	// Insecure Random
	a.rules["INSECURE_RANDOM"] = &SecurityRule{
		ID:          "INSECURE_RANDOM",
		Name:        "Insecure Random Number Generation",
		Description: "Use of insecure random number generation for security purposes",
		Category:    "insecure-random",
		Level:       SecurityLevelMedium,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)math\.random`),
			regexp.MustCompile(`(?i)random\.random`),
			regexp.MustCompile(`(?i)rand\.intn`),
		},
		FileTypes: []string{".go", ".java", ".py", ".js", ".ts"},
	}
}

// registerCustomRules registers user-provided custom rules.
func (a *Analyzer) registerCustomRules(rules []*SecurityRule) {
	for _, rule := range rules {
		a.rules[rule.ID] = rule
	}
}

// Helper methods

func (a *Analyzer) shouldExcludeFile(filePath string) bool {
	for _, pattern := range a.config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return true
		}
	}
	return false
}

func (a *Analyzer) isCategoryEnabled(category string) bool {
	if len(a.config.EnabledCategories) == 0 {
		return true
	}
	
	for _, enabled := range a.config.EnabledCategories {
		if enabled == category {
			return true
		}
	}
	return false
}

func (a *Analyzer) matchesFileType(filePath string, fileTypes []string) bool {
	if len(fileTypes) == 0 {
		return true
	}
	
	ext := filepath.Ext(filePath)
	for _, fileType := range fileTypes {
		if ext == fileType {
			return true
		}
	}
	return false
}

func (a *Analyzer) isSuspiciousPackageName(name string) bool {
	// Check for common typosquatting patterns
	suspicious := []string{
		"request", "urllib", "numpy", "pandas", "tensorflow",
		"express", "lodash", "moment", "axios", "react",
	}
	
	lower := strings.ToLower(name)
	for _, sus := range suspicious {
		if strings.Contains(lower, sus) && lower != sus {
			// Potential typosquatting
			return true
		}
	}
	
	return false
}

func (a *Analyzer) isDevelopmentPackage(name string) bool {
	devPatterns := []string{
		"test", "mock", "debug", "dev", "development",
		"jest", "mocha", "chai", "sinon", "karma",
	}
	
	lower := strings.ToLower(name)
	for _, pattern := range devPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	
	return false
}

func (a *Analyzer) isOutdatedVersion(name, version string) bool {
	// Simplified check - in production, this would integrate with vulnerability databases
	// For now, just check for very old version patterns
	if strings.Contains(version, "0.") || strings.HasPrefix(version, "1.") {
		return true
	}
	
	return false
}

func (a *Analyzer) getRemediation(ruleID string) string {
	remediations := map[string]string{
		"HARDCODED_PASSWORD": "Use environment variables or secure configuration management",
		"HARDCODED_API_KEY":  "Store API keys in environment variables or secure vaults",
		"SQL_INJECTION":      "Use parameterized queries or prepared statements",
		"COMMAND_INJECTION":  "Validate and sanitize all user inputs before executing commands",
		"PATH_TRAVERSAL":     "Validate file paths and use allowlists for permitted directories",
		"WEAK_CRYPTO":        "Use strong cryptographic algorithms like SHA-256 or AES",
		"INSECURE_RANDOM":    "Use cryptographically secure random number generators",
	}
	
	if remediation, ok := remediations[ruleID]; ok {
		return remediation
	}
	
	return "Review the code and apply security best practices"
}

func (a *Analyzer) getReferences(ruleID string) []string {
	references := map[string][]string{
		"HARDCODED_PASSWORD": {
			"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
		},
		"SQL_INJECTION": {
			"https://owasp.org/www-community/attacks/SQL_Injection",
		},
		"COMMAND_INJECTION": {
			"https://owasp.org/www-community/attacks/Command_Injection",
		},
	}
	
	if refs, ok := references[ruleID]; ok {
		return refs
	}
	
	return []string{}
}

// String returns a string representation of the security level.
func (s SecurityLevel) String() string {
	switch s {
	case SecurityLevelInfo:
		return "INFO"
	case SecurityLevelLow:
		return "LOW"
	case SecurityLevelMedium:
		return "MEDIUM"
	case SecurityLevelHigh:
		return "HIGH"
	case SecurityLevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}