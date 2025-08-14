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

package multiplatform

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
)

// KotlinGradleParser parses Kotlin Gradle build files.
type KotlinGradleParser struct{}

var (
	kotlinDependencyRegex = regexp.MustCompile(`(?:implementation|api|testImplementation|runtimeOnly|compileOnly)\s*\(\s*"([^"]+)"\s*\)`)
	kotlinPluginRegex     = regexp.MustCompile(`id\s*\(\s*"([^"]+)"\s*\)\s*version\s*"([^"]+)"`)
)

func (p *KotlinGradleParser) ParseDependencies(content, filePath string) ([]*extractor.Package, error) {
	var packages []*extractor.Package
	
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}
		
		// Parse dependencies
		if matches := kotlinDependencyRegex.FindStringSubmatch(line); len(matches) > 1 {
			if pkg := parseGradleDependency(matches[1], filePath); pkg != nil {
				packages = append(packages, pkg)
			}
		}
		
		// Parse plugins
		if matches := kotlinPluginRegex.FindStringSubmatch(line); len(matches) > 2 {
			pkg := &extractor.Package{
				Name:      matches[1],
				Version:   matches[2],
				Locations: []string{filePath},
				Metadata: map[string]interface{}{
					"type":     "plugin",
					"language": "kotlin",
				},
			}
			packages = append(packages, pkg)
		}
	}
	
	return packages, scanner.Err()
}

// ScalaSbtParser parses Scala SBT build files.
type ScalaSbtParser struct{}

var (
	scalaDependencyRegex = regexp.MustCompile(`"([^"]+)"\s*%\s*"([^"]+)"\s*%\s*"([^"]+)"`)
	scalaLibDepsRegex    = regexp.MustCompile(`libraryDependencies\s*\+?=\s*Seq\s*\(`)
)

func (p *ScalaSbtParser) ParseDependencies(content, filePath string) ([]*extractor.Package, error) {
	var packages []*extractor.Package
	
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}
		
		// Parse Scala dependencies: "group" % "artifact" % "version"
		if matches := scalaDependencyRegex.FindStringSubmatch(line); len(matches) > 3 {
			pkg := &extractor.Package{
				Name:      matches[1] + ":" + matches[2],
				Version:   matches[3],
				Locations: []string{filePath},
				Metadata: map[string]interface{}{
					"group":    matches[1],
					"artifact": matches[2],
					"language": "scala",
				},
			}
			packages = append(packages, pkg)
		}
	}
	
	return packages, scanner.Err()
}

// ClojureParser parses Clojure dependency files.
type ClojureParser struct{}

var (
	clojureDependencyRegex = regexp.MustCompile(`\[([^/\s]+)/([^\s\]]+)\s+"([^"]+)"\]`)
	clojureSimpleDepsRegex = regexp.MustCompile(`([^/\s]+)/([^\s\{]+)\s+\{[^}]*:mvn/version\s+"([^"]+)"`)
)

func (p *ClojureParser) ParseDependencies(content, filePath string) ([]*extractor.Package, error) {
	var packages []*extractor.Package
	
	// Parse Leiningen style: [group/artifact "version"]
	matches := clojureDependencyRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 3 {
			pkg := &extractor.Package{
				Name:      match[1] + "/" + match[2],
				Version:   match[3],
				Locations: []string{filePath},
				Metadata: map[string]interface{}{
					"group":    match[1],
					"artifact": match[2],
					"language": "clojure",
				},
			}
			packages = append(packages, pkg)
		}
	}
	
	// Parse deps.edn style: group/artifact {:mvn/version "version"}
	matches = clojureSimpleDepsRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 3 {
			pkg := &extractor.Package{
				Name:      match[1] + "/" + match[2],
				Version:   match[3],
				Locations: []string{filePath},
				Metadata: map[string]interface{}{
					"group":    match[1],
					"artifact": match[2],
					"language": "clojure",
					"format":   "deps.edn",
				},
			}
			packages = append(packages, pkg)
		}
	}
	
	return packages, nil
}

// ZigParser parses Zig build files.
type ZigParser struct{}

var (
	zigDependencyRegex = regexp.MustCompile(`\.dependency\s*\(\s*"([^"]+)"\s*,\s*\.{[^}]*\.url\s*=\s*"([^"]+)"`)
	zigModuleRegex     = regexp.MustCompile(`\.addModule\s*\(\s*"([^"]+)"\s*,`)
)

func (p *ZigParser) ParseDependencies(content, filePath string) ([]*extractor.Package, error) {
	var packages []*extractor.Package
	
	// Parse .dependency() calls
	matches := zigDependencyRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			pkg := &extractor.Package{
				Name:      match[1],
				Version:   "", // Zig often uses git URLs without explicit versions
				Locations: []string{filePath},
				Metadata: map[string]interface{}{
					"url":      match[2],
					"language": "zig",
				},
			}
			packages = append(packages, pkg)
		}
	}
	
	return packages, nil
}

// NimParser parses Nim nimble files.
type NimParser struct{}

var (
	nimRequiresRegex = regexp.MustCompile(`requires\s+"([^"]+)(?:\s*>=?\s*([^"]+))?"`)
)

func (p *NimParser) ParseDependencies(content, filePath string) ([]*extractor.Package, error) {
	var packages []*extractor.Package
	
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse requires statements
		if matches := nimRequiresRegex.FindStringSubmatch(line); len(matches) > 1 {
			name := matches[1]
			version := ""
			if len(matches) > 2 && matches[2] != "" {
				version = matches[2]
			}
			
			pkg := &extractor.Package{
				Name:      name,
				Version:   version,
				Locations: []string{filePath},
				Metadata: map[string]interface{}{
					"language": "nim",
				},
			}
			packages = append(packages, pkg)
		}
	}
	
	return packages, scanner.Err()
}

// CrystalParser parses Crystal shard files.
type CrystalParser struct{}

func (p *CrystalParser) ParseDependencies(content, filePath string) ([]*extractor.Package, error) {
	var packages []*extractor.Package
	
	// Simple YAML-like parsing for Crystal shards
	scanner := bufio.NewScanner(strings.NewReader(content))
	inDependencies := false
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "dependencies:" {
			inDependencies = true
			continue
		}
		
		if inDependencies {
			// Check if we've left the dependencies section
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && line != "" {
				inDependencies = false
				continue
			}
			
			// Parse dependency line: "  name:"
			if strings.Contains(line, ":") && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
				parts := strings.Split(line, ":")
				if len(parts) > 0 {
					name := strings.TrimSpace(parts[0])
					if name != "" {
						pkg := &extractor.Package{
							Name:      name,
							Version:   "", // Crystal often uses git refs
							Locations: []string{filePath},
							Metadata: map[string]interface{}{
								"language": "crystal",
							},
						}
						packages = append(packages, pkg)
					}
				}
			}
		}
	}
	
	return packages, scanner.Err()
}

// parseGradleDependency parses a Gradle-style dependency string.
func parseGradleDependency(depStr, filePath string) *extractor.Package {
	parts := strings.Split(depStr, ":")
	if len(parts) < 2 {
		return nil
	}
	
	var name, version string
	if len(parts) == 2 {
		name = parts[0] + ":" + parts[1]
		version = ""
	} else if len(parts) >= 3 {
		name = parts[0] + ":" + parts[1]
		version = parts[2]
	}
	
	if name == "" {
		return nil
	}
	
	return &extractor.Package{
		Name:      name,
		Version:   version,
		Locations: []string{filePath},
		Metadata: map[string]interface{}{
			"group":    parts[0],
			"artifact": parts[1],
		},
	}
}