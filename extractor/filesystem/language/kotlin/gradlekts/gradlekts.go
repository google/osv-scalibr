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

// Package gradlekts extracts Kotlin Gradle build files.
package gradlekts

import (
	"bufio"
	"context"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "kotlin/gradlekts"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will unmarshal.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

var (
	// Regex to match Kotlin dependency declarations
	// Matches: implementation("group:artifact:version")
	// Matches: api("group:artifact:version")
	// Matches: testImplementation("group:artifact:version")
	reDependency = regexp.MustCompile(`(?:implementation|api|testImplementation|runtimeOnly|compileOnly)\s*\(\s*"([^"]+)"\s*\)`)
	
	// Regex to match version catalog references
	// Matches: implementation(libs.some.library)
	reVersionCatalog = regexp.MustCompile(`(?:implementation|api|testImplementation|runtimeOnly|compileOnly)\s*\(\s*libs\.([^)]+)\s*\)`)
	
	// Regex to match plugin declarations
	// Matches: id("plugin.id") version "1.0.0"
	rePlugin = regexp.MustCompile(`id\s*\(\s*"([^"]+)"\s*\)\s*version\s*"([^"]+)"`)
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal.
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts Kotlin packages from Gradle Kotlin build files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Kotlin Gradle extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 1 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSAny}
}

// FileRequired returns true if the specified file matches Kotlin Gradle build files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	// Check file size if specified
	if e.maxFileSizeBytes > 0 {
		fileinfo, err := api.Stat()
		if err != nil {
			log.Debugf("Failed to stat file %q: %v", api.Path(), err)
			return false
		}
		if fileinfo.Size() > e.maxFileSizeBytes {
			log.Debugf("File %q is too large (%d bytes, max %d)", api.Path(), fileinfo.Size(), e.maxFileSizeBytes)
			return false
		}
	}
	
	// Check for Kotlin Gradle build files
	if strings.HasSuffix(api.Path(), "build.gradle.kts") ||
		strings.HasSuffix(api.Path(), "settings.gradle.kts") {
		return true
	}
	
	return false
}

// Extract extracts packages from Kotlin Gradle build files.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages := []*extractor.Package{}
	
	scanner := bufio.NewScanner(input.Reader)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}
		
		// Extract regular dependencies
		if matches := reDependency.FindStringSubmatch(line); len(matches) > 1 {
			pkg := parseDependencyString(matches[1], input.Path, lineNum)
			if pkg != nil {
				packages = append(packages, pkg)
			}
		}
		
		// Extract plugin dependencies
		if matches := rePlugin.FindStringSubmatch(line); len(matches) > 2 {
			pkg := &extractor.Package{
				Name:      matches[1],
				Version:   matches[2],
				Locations: []string{input.Path},
				PURLType:  purl.TypeMaven, // Gradle plugins are typically Maven artifacts
			}
			packages = append(packages, pkg)
		}
		
		// TODO: Handle version catalog references (libs.xxx)
		// This would require parsing gradle/libs.versions.toml
		if matches := reVersionCatalog.FindStringSubmatch(line); len(matches) > 1 {
			log.Debugf("Found version catalog reference: %s (not yet supported)", matches[1])
		}
	}
	
	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, err
	}
	
	return inventory.Inventory{Packages: packages}, nil
}

// parseDependencyString parses a dependency string like "group:artifact:version"
func parseDependencyString(depStr, filePath string, lineNum int) *extractor.Package {
	parts := strings.Split(depStr, ":")
	if len(parts) < 2 {
		log.Debugf("Invalid dependency format at %s:%d: %s", filePath, lineNum, depStr)
		return nil
	}
	
	var name, version string
	
	if len(parts) == 2 {
		// Format: "group:artifact" (version managed elsewhere)
		name = parts[0] + ":" + parts[1]
		version = ""
	} else if len(parts) >= 3 {
		// Format: "group:artifact:version" or "group:artifact:version:classifier"
		name = parts[0] + ":" + parts[1]
		version = parts[2]
	}
	
	// Skip if no actual package name
	if name == "" {
		return nil
	}
	
	return &extractor.Package{
		Name:      name,
		Version:   version,
		Locations: []string{filePath},
		PURLType:  purl.TypeMaven, // Kotlin/Gradle uses Maven-style coordinates
	}
}
