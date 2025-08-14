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

// Package multiplatform provides advanced ecosystem detection and extraction capabilities.
package multiplatform

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this advanced extractor.
	Name = "multiplatform/ecosystem-detector"
)

// EcosystemPattern defines how to detect and parse a specific ecosystem.
type EcosystemPattern struct {
	Name           string
	FilePatterns   []string
	ContentRegexes []*regexp.Regexp
	PURLType       string
	Parser         DependencyParser
}

// DependencyParser defines how to parse dependencies from file content.
type DependencyParser interface {
	ParseDependencies(content string, filePath string) ([]*extractor.Package, error)
}

// Config is the configuration for the advanced ecosystem detector.
type Config struct {
	// EnabledEcosystems specifies which ecosystems to detect
	EnabledEcosystems []string
	// MaxConcurrentParsers limits parallel parsing
	MaxConcurrentParsers int
	// EnableCaching enables intelligent caching of parse results
	EnableCaching bool
	// MaxFileSizeBytes limits the size of files to parse
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		EnabledEcosystems: []string{
			"kotlin", "scala", "clojure", "zig", "nim", "crystal",
		},
		MaxConcurrentParsers: 4,
		EnableCaching:        true,
		MaxFileSizeBytes:     10 * 1024 * 1024, // 10MB
	}
}

// Extractor provides advanced multi-ecosystem detection and extraction.
type Extractor struct {
	config     Config
	ecosystems map[string]*EcosystemPattern
	cache      sync.Map // File path -> parsed packages cache
	semaphore  chan struct{}
}

// New creates a new advanced ecosystem extractor.
func New(cfg Config) *Extractor {
	e := &Extractor{
		config:     cfg,
		ecosystems: make(map[string]*EcosystemPattern),
		semaphore:  make(chan struct{}, cfg.MaxConcurrentParsers),
	}
	
	e.registerEcosystems()
	return e
}

// NewDefault returns an extractor with default configuration.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 1 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSAny}
}

// FileRequired determines if a file should be processed by this extractor.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	
	// Check file size limit
	if e.config.MaxFileSizeBytes > 0 {
		if info, err := api.Stat(); err == nil {
			if info.Size() > e.config.MaxFileSizeBytes {
				return false
			}
		}
	}
	
	// Check against all registered ecosystem patterns
	for ecosystemName, pattern := range e.ecosystems {
		if !e.isEcosystemEnabled(ecosystemName) {
			continue
		}
		
		for _, filePattern := range pattern.FilePatterns {
			if matched, _ := filepath.Match(filePattern, filepath.Base(path)); matched {
				return true
			}
			
			// Also check full path for patterns like "*/gradle/*"
			if strings.Contains(filePattern, "/") {
				if matched, _ := filepath.Match(filePattern, path); matched {
					return true
				}
			}
		}
	}
	
	return false
}

// Extract processes a file and extracts package information.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Check cache first
	if e.config.EnableCaching {
		if cached, ok := e.cache.Load(input.Path); ok {
			if packages, ok := cached.([]*extractor.Package); ok {
				log.Debugf("Cache hit for %s", input.Path)
				return inventory.Inventory{Packages: packages}, nil
			}
		}
	}
	
	// Acquire semaphore for concurrent processing
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return inventory.Inventory{}, ctx.Err()
	}
	
	// Read file content
	content, err := e.readFileContent(input)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read file %s: %w", input.Path, err)
	}
	
	var allPackages []*extractor.Package
	
	// Try each ecosystem pattern
	for ecosystemName, pattern := range e.ecosystems {
		if !e.isEcosystemEnabled(ecosystemName) {
			continue
		}
		
		if e.matchesEcosystem(input.Path, content, pattern) {
			packages, err := pattern.Parser.ParseDependencies(content, input.Path)
			if err != nil {
				log.Debugf("Failed to parse %s as %s: %v", input.Path, ecosystemName, err)
				continue
			}
			
			// Add ecosystem metadata
			for _, pkg := range packages {
				pkg.PURLType = pattern.PURLType
				if pkg.Metadata == nil {
					pkg.Metadata = make(map[string]interface{})
				}
				if metadata, ok := pkg.Metadata.(map[string]interface{}); ok {
					metadata["ecosystem"] = ecosystemName
					metadata["detector"] = Name
				}
			}
			
			allPackages = append(allPackages, packages...)
			log.Debugf("Extracted %d packages from %s using %s parser", len(packages), input.Path, ecosystemName)
		}
	}
	
	// Cache results
	if e.config.EnableCaching && len(allPackages) > 0 {
		e.cache.Store(input.Path, allPackages)
	}
	
	return inventory.Inventory{Packages: allPackages}, nil
}

// registerEcosystems sets up all supported ecosystem patterns.
func (e *Extractor) registerEcosystems() {
	// Kotlin ecosystem
	e.ecosystems["kotlin"] = &EcosystemPattern{
		Name: "kotlin",
		FilePatterns: []string{
			"build.gradle.kts",
			"settings.gradle.kts",
			"*.gradle.kts",
		},
		ContentRegexes: []*regexp.Regexp{
			regexp.MustCompile(`(?:implementation|api|testImplementation|runtimeOnly|compileOnly)\s*\(`),
		},
		PURLType: purl.TypeMaven,
		Parser:   &KotlinGradleParser{},
	}
	
	// Scala ecosystem
	e.ecosystems["scala"] = &EcosystemPattern{
		Name: "scala",
		FilePatterns: []string{
			"build.sbt",
			"*.sbt",
			"project/*.scala",
		},
		ContentRegexes: []*regexp.Regexp{
			regexp.MustCompile(`libraryDependencies\s*\+?=`),
			regexp.MustCompile(`"[^"]+"\s*%\s*"[^"]+"\s*%\s*"[^"]+"`),
		},
		PURLType: purl.TypeMaven,
		Parser:   &ScalaSbtParser{},
	}
	
	// Clojure ecosystem
	e.ecosystems["clojure"] = &EcosystemPattern{
		Name: "clojure",
		FilePatterns: []string{
			"deps.edn",
			"project.clj",
			"shadow-cljs.edn",
		},
		ContentRegexes: []*regexp.Regexp{
			regexp.MustCompile(`:dependencies\s*\{`),
			regexp.MustCompile(`\[.*\/.*\s+".*"\]`),
		},
		PURLType: purl.TypeMaven,
		Parser:   &ClojureParser{},
	}
	
	// Zig ecosystem
	e.ecosystems["zig"] = &EcosystemPattern{
		Name: "zig",
		FilePatterns: []string{
			"build.zig",
			"build.zig.zon",
		},
		ContentRegexes: []*regexp.Regexp{
			regexp.MustCompile(`\.dependency\s*\(`),
			regexp.MustCompile(`\.addModule\s*\(`),
		},
		PURLType: "zig", // Custom PURL type for Zig
		Parser:   &ZigParser{},
	}
	
	// Nim ecosystem
	e.ecosystems["nim"] = &EcosystemPattern{
		Name: "nim",
		FilePatterns: []string{
			"*.nimble",
			"nimble.lock",
		},
		ContentRegexes: []*regexp.Regexp{
			regexp.MustCompile(`requires\s+"[^"]+"`),
		},
		PURLType: "nim", // Custom PURL type for Nim
		Parser:   &NimParser{},
	}
	
	// Crystal ecosystem
	e.ecosystems["crystal"] = &EcosystemPattern{
		Name: "crystal",
		FilePatterns: []string{
			"shard.yml",
			"shard.lock",
		},
		ContentRegexes: []*regexp.Regexp{
			regexp.MustCompile(`dependencies:`),
			regexp.MustCompile(`github:\s*[^/]+/[^/]+`),
		},
		PURLType: "crystal", // Custom PURL type for Crystal
		Parser:   &CrystalParser{},
	}
}

// matchesEcosystem checks if a file matches a specific ecosystem pattern.
func (e *Extractor) matchesEcosystem(filePath, content string, pattern *EcosystemPattern) bool {
	// Check file pattern match
	matched := false
	for _, filePattern := range pattern.FilePatterns {
		if match, _ := filepath.Match(filePattern, filepath.Base(filePath)); match {
			matched = true
			break
		}
		if strings.Contains(filePattern, "/") {
			if match, _ := filepath.Match(filePattern, filePath); match {
				matched = true
				break
			}
		}
	}
	
	if !matched {
		return false
	}
	
	// Check content patterns for additional validation
	for _, regex := range pattern.ContentRegexes {
		if regex.MatchString(content) {
			return true
		}
	}
	
	// If no content regexes defined, file pattern match is sufficient
	return len(pattern.ContentRegexes) == 0
}

// isEcosystemEnabled checks if an ecosystem is enabled in the configuration.
func (e *Extractor) isEcosystemEnabled(ecosystem string) bool {
	if len(e.config.EnabledEcosystems) == 0 {
		return true // All enabled by default
	}
	
	for _, enabled := range e.config.EnabledEcosystems {
		if enabled == ecosystem {
			return true
		}
	}
	return false
}

// readFileContent reads the entire content of a file.
func (e *Extractor) readFileContent(input *filesystem.ScanInput) (string, error) {
	content := make([]byte, 0, 1024)
	buffer := make([]byte, 1024)
	
	for {
		n, err := input.Reader.Read(buffer)
		if n > 0 {
			content = append(content, buffer[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return "", err
		}
	}
	
	return string(content), nil
}