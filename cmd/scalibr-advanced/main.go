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

// Package main provides an advanced CLI for OSV-SCALIBR with enhanced features.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem/language/multiplatform"
	"github.com/google/osv-scalibr/performance/optimizer"
	"github.com/google/osv-scalibr/security/analyzer"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	scalibr "github.com/google/osv-scalibr"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// Config represents the advanced CLI configuration.
type Config struct {
	// Scan configuration
	ScanPath             string
	OutputFormat         string
	OutputFile           string
	Verbose              bool
	
	// Advanced features
	EnableSecurity       bool
	EnableOptimization   bool
	EnableMultiEcosystem bool
	
	// Performance tuning
	MaxWorkers           int
	MemoryLimit          string
	TimeoutPerFile       time.Duration
	
	// Security options
	SecurityCategories   string
	SecurityLevel        string
	
	// Ecosystem options
	EnabledEcosystems    string
	
	// Output options
	IncludeMetadata      bool
	IncludePerformance   bool
	IncludeSecurity      bool
}

// AdvancedScanResult extends the basic scan result with advanced features.
type AdvancedScanResult struct {
	*scalibr.ScanResult
	SecurityFindings     []analyzer.SecurityFinding    `json:"security_findings,omitempty"`
	PerformanceStats     *optimizer.OptimizationStats  `json:"performance_stats,omitempty"`
	EcosystemsDetected   []string                       `json:"ecosystems_detected,omitempty"`
	AdvancedMetadata     map[string]interface{}         `json:"advanced_metadata,omitempty"`
}

func main() {
	config := parseFlags()
	
	if config.Verbose {
		log.SetLogger(&log.DefaultLogger{Verbose: true})
	}
	
	ctx := context.Background()
	
	// Run the advanced scan
	result, err := runAdvancedScan(ctx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Output results
	if err := outputResults(result, config); err != nil {
		fmt.Fprintf(os.Stderr, "Error outputting results: %v\n", err)
		os.Exit(1)
	}
	
	// Print summary
	printSummary(result, config)
}

func parseFlags() *Config {
	config := &Config{}
	
	// Basic flags
	flag.StringVar(&config.ScanPath, "path", ".", "Path to scan")
	flag.StringVar(&config.OutputFormat, "format", "json", "Output format (json, yaml, text)")
	flag.StringVar(&config.OutputFile, "output", "", "Output file (default: stdout)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose logging")
	
	// Advanced feature flags
	flag.BoolVar(&config.EnableSecurity, "security", true, "Enable security analysis")
	flag.BoolVar(&config.EnableOptimization, "optimize", true, "Enable performance optimization")
	flag.BoolVar(&config.EnableMultiEcosystem, "multi-ecosystem", true, "Enable multi-ecosystem detection")
	
	// Performance flags
	flag.IntVar(&config.MaxWorkers, "workers", runtime.NumCPU()*2, "Maximum concurrent workers")
	flag.StringVar(&config.MemoryLimit, "memory-limit", "1GB", "Memory limit (e.g., 512MB, 2GB)")
	flag.DurationVar(&config.TimeoutPerFile, "file-timeout", 30*time.Second, "Timeout per file")
	
	// Security flags
	flag.StringVar(&config.SecurityCategories, "security-categories", "all", "Security categories to check")
	flag.StringVar(&config.SecurityLevel, "security-level", "medium", "Minimum security level to report")
	
	// Ecosystem flags
	flag.StringVar(&config.EnabledEcosystems, "ecosystems", "all", "Enabled ecosystems (comma-separated)")
	
	// Output flags
	flag.BoolVar(&config.IncludeMetadata, "include-metadata", true, "Include advanced metadata")
	flag.BoolVar(&config.IncludePerformance, "include-performance", false, "Include performance statistics")
	flag.BoolVar(&config.IncludeSecurity, "include-security", true, "Include security findings")
	
	flag.Parse()
	
	return config
}

func runAdvancedScan(ctx context.Context, config *Config) (*AdvancedScanResult, error) {
	// Initialize components
	var plugins []plugin.Plugin
	
	// Add multi-ecosystem extractor if enabled
	if config.EnableMultiEcosystem {
		ecosystemConfig := multiplatform.DefaultConfig()
		if config.EnabledEcosystems != "all" {
			ecosystemConfig.EnabledEcosystems = strings.Split(config.EnabledEcosystems, ",")
		}
		plugins = append(plugins, multiplatform.New(ecosystemConfig))
	}
	
	// Initialize performance optimizer
	var perfOptimizer *optimizer.Optimizer
	if config.EnableOptimization {
		optimizerConfig := optimizer.DefaultConfig()
		optimizerConfig.MaxConcurrentWorkers = config.MaxWorkers
		optimizerConfig.TimeoutPerFile = config.TimeoutPerFile
		
		// Parse memory limit
		if memLimit, err := parseMemoryLimit(config.MemoryLimit); err == nil {
			optimizerConfig.MemoryLimit = memLimit
		}
		
		perfOptimizer = optimizer.New(optimizerConfig)
	}
	
	// Initialize security analyzer
	var secAnalyzer *analyzer.Analyzer
	if config.EnableSecurity {
		secConfig := analyzer.DefaultConfig()
		if config.SecurityCategories != "all" {
			secConfig.EnabledCategories = strings.Split(config.SecurityCategories, ",")
		}
		secAnalyzer = analyzer.New(secConfig)
	}
	
	// Create scan configuration
	scanConfig := &scalibr.ScanConfig{
		ScanRoots: []*scalibrfs.ScanRoot{
			{
				FS:   scalibrfs.DirFS(config.ScanPath),
				Path: config.ScanPath,
			},
		},
		Plugins: plugins,
		Capabilities: &plugin.Capabilities{
			OS:            getOSCapability(),
			Network:       plugin.NetworkOnline,
			DirectFS:      true,
			RunningSystem: true,
		},
	}
	
	// Run the scan
	scanner := scalibr.New()
	scanResult := scanner.Scan(ctx, scanConfig)
	
	// Create advanced result
	advancedResult := &AdvancedScanResult{
		ScanResult:       scanResult,
		EcosystemsDetected: extractEcosystems(scanResult),
		AdvancedMetadata: map[string]interface{}{
			"scan_mode":     "advanced",
			"cli_version":   "1.0.0",
			"go_version":    runtime.Version(),
			"platform":      runtime.GOOS + "/" + runtime.GOARCH,
			"scan_duration": scanResult.EndTime.Sub(scanResult.StartTime).String(),
		},
	}
	
	// Run security analysis if enabled
	if config.EnableSecurity && secAnalyzer != nil {
		secFindings, err := secAnalyzer.AnalyzeInventory(ctx, &scanResult.Inventory)
		if err != nil {
			log.Errorf("Security analysis failed: %v", err)
		} else {
			advancedResult.SecurityFindings = secFindings
		}
	}
	
	// Add performance stats if enabled
	if config.IncludePerformance && perfOptimizer != nil {
		stats := perfOptimizer.GetStats()
		advancedResult.PerformanceStats = &stats
	}
	
	return advancedResult, nil
}

func outputResults(result *AdvancedScanResult, config *Config) error {
	var output []byte
	var err error
	
	switch strings.ToLower(config.OutputFormat) {
	case "json":
		output, err = json.MarshalIndent(result, "", "  ")
	case "yaml":
		// For simplicity, using JSON format - real implementation would use yaml package
		output, err = json.MarshalIndent(result, "", "  ")
	case "text":
		output = []byte(formatTextOutput(result))
	default:
		return fmt.Errorf("unsupported output format: %s", config.OutputFormat)
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}
	
	// Write to file or stdout
	if config.OutputFile != "" {
		return os.WriteFile(config.OutputFile, output, 0644)
	}
	
	fmt.Print(string(output))
	return nil
}

func formatTextOutput(result *AdvancedScanResult) string {
	var sb strings.Builder
	
	sb.WriteString("=== OSV-SCALIBR Advanced Scan Results ===\n\n")
	
	// Basic scan info
	sb.WriteString(fmt.Sprintf("Scan Status: %s\n", result.Status.Status))
	sb.WriteString(fmt.Sprintf("Start Time: %s\n", result.StartTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("End Time: %s\n", result.EndTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Duration: %s\n", result.EndTime.Sub(result.StartTime)))
	sb.WriteString("\n")
	
	// Packages found
	sb.WriteString(fmt.Sprintf("Packages Found: %d\n", len(result.Inventory.Packages)))
	if len(result.EcosystemsDetected) > 0 {
		sb.WriteString(fmt.Sprintf("Ecosystems Detected: %s\n", strings.Join(result.EcosystemsDetected, ", ")))
	}
	sb.WriteString("\n")
	
	// Security findings
	if len(result.SecurityFindings) > 0 {
		sb.WriteString("=== Security Findings ===\n")
		for _, finding := range result.SecurityFindings {
			sb.WriteString(fmt.Sprintf("[%s] %s\n", finding.Level, finding.Title))
			sb.WriteString(fmt.Sprintf("  Location: %s\n", finding.Location))
			sb.WriteString(fmt.Sprintf("  Description: %s\n", finding.Description))
			if finding.Remediation != "" {
				sb.WriteString(fmt.Sprintf("  Remediation: %s\n", finding.Remediation))
			}
			sb.WriteString("\n")
		}
	}
	
	// Performance stats
	if result.PerformanceStats != nil {
		sb.WriteString("=== Performance Statistics ===\n")
		sb.WriteString(fmt.Sprintf("Files Processed: %d\n", result.PerformanceStats.FilesProcessed))
		sb.WriteString(fmt.Sprintf("Files Skipped: %d\n", result.PerformanceStats.FilesSkipped))
		sb.WriteString(fmt.Sprintf("Cache Hit Rate: %.2f%%\n", 
			float64(result.PerformanceStats.CacheHits)/float64(result.PerformanceStats.CacheHits+result.PerformanceStats.CacheMisses)*100))
		sb.WriteString(fmt.Sprintf("Average File Time: %s\n", result.PerformanceStats.AverageFileTime))
		sb.WriteString(fmt.Sprintf("Peak Memory Usage: %d bytes\n", result.PerformanceStats.PeakMemoryUsage))
	}
	
	return sb.String()
}

func printSummary(result *AdvancedScanResult, config *Config) {
	if !config.Verbose {
		return
	}
	
	fmt.Fprintf(os.Stderr, "\n=== Scan Summary ===\n")
	fmt.Fprintf(os.Stderr, "Packages: %d\n", len(result.Inventory.Packages))
	fmt.Fprintf(os.Stderr, "Vulnerabilities: %d\n", len(result.Inventory.PackageVulns))
	
	if len(result.SecurityFindings) > 0 {
		fmt.Fprintf(os.Stderr, "Security Issues: %d\n", len(result.SecurityFindings))
	}
	
	if result.PerformanceStats != nil {
		fmt.Fprintf(os.Stderr, "Files Processed: %d\n", result.PerformanceStats.FilesProcessed)
		fmt.Fprintf(os.Stderr, "Processing Time: %s\n", result.PerformanceStats.TotalProcessingTime)
	}
	
	fmt.Fprintf(os.Stderr, "Status: %s\n", result.Status.Status)
}

// Helper functions

func getOSCapability() plugin.OS {
	switch runtime.GOOS {
	case "windows":
		return plugin.OSWindows
	case "darwin":
		return plugin.OSMac
	case "linux":
		return plugin.OSLinux
	default:
		return plugin.OSUnknown
	}
}

func extractEcosystems(result *scalibr.ScanResult) []string {
	ecosystems := make(map[string]bool)
	
	for _, pkg := range result.Inventory.Packages {
		if metadata, ok := pkg.Metadata.(map[string]interface{}); ok {
			if ecosystem, ok := metadata["ecosystem"].(string); ok {
				ecosystems[ecosystem] = true
			}
		}
		
		// Also check PURL type
		if pkg.PURLType != "" {
			ecosystems[pkg.PURLType] = true
		}
	}
	
	var result_ecosystems []string
	for ecosystem := range ecosystems {
		result_ecosystems = append(result_ecosystems, ecosystem)
	}
	
	return result_ecosystems
}

func parseMemoryLimit(limit string) (int64, error) {
	limit = strings.ToUpper(strings.TrimSpace(limit))
	
	var multiplier int64 = 1
	if strings.HasSuffix(limit, "KB") {
		multiplier = 1024
		limit = strings.TrimSuffix(limit, "KB")
	} else if strings.HasSuffix(limit, "MB") {
		multiplier = 1024 * 1024
		limit = strings.TrimSuffix(limit, "MB")
	} else if strings.HasSuffix(limit, "GB") {
		multiplier = 1024 * 1024 * 1024
		limit = strings.TrimSuffix(limit, "GB")
	}
	
	var value int64
	if _, err := fmt.Sscanf(limit, "%d", &value); err != nil {
		return 0, err
	}
	
	return value * multiplier, nil
}