// Copyright 2026 Google LLC
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

// Package packageswift extracts Package.swift files for Swift projects.
package packageswift

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "swift/packageswift"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by FileRequired.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Extractor extracts packages from Package.swift files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Package.swift extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is named "Package.swift".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "Package.swift" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract parses and extracts dependency data from a Package.swift file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(input)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read Package.swift: %w", err)
	}

	packages := parse(string(content))

	result := []*extractor.Package{}
	for _, pkg := range packages {
		result = append(result, &extractor.Package{
			Name:     pkg.Name,
			Version:  pkg.Version,
			PURLType: purl.TypeSwift,
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return result, nil
}

// pkg represents a parsed package entry from the Package.swift file.
type pkg struct {
	Name    string
	Version string
}

// parse extracts package dependencies from a Package.swift file content.
// It looks for .package(url:...) declarations with version specifiers.
func parse(content string) []pkg {
	// Strip comments to avoid false matches in commented code.
	content = stripComments(content)

	var packages []pkg

	// Match .package(url: "...", from: "X.Y.Z")
	fromRe := regexp.MustCompile(`(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*from\s*:\s*"([^"]+)"\s*\)`)
	for _, match := range fromRe.FindAllStringSubmatch(content, -1) {
		url := match[1]
		version := match[2]
		if name := normalizeSwiftURL(url); name != "" {
			packages = append(packages, pkg{Name: name, Version: version})
		}
	}

	// Match .package(url: "...", exact: "X.Y.Z")
	exactRe := regexp.MustCompile(`(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*exact\s*:\s*"([^"]+)"\s*\)`)
	for _, match := range exactRe.FindAllStringSubmatch(content, -1) {
		url := match[1]
		version := match[2]
		if name := normalizeSwiftURL(url); name != "" {
			packages = append(packages, pkg{Name: name, Version: version})
		}
	}

	// Match .package(url: "...", .exact("X.Y.Z"))
	dotExactRe := regexp.MustCompile(`(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.exact\s*\(\s*"([^"]+)"\s*\)\s*\)`)
	for _, match := range dotExactRe.FindAllStringSubmatch(content, -1) {
		url := match[1]
		version := match[2]
		if name := normalizeSwiftURL(url); name != "" {
			packages = append(packages, pkg{Name: name, Version: version})
		}
	}

	// Match .package(url: "...", .upToNextMajor(from: "X.Y.Z"))
	upToNextMajorRe := regexp.MustCompile(`(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.upToNextMajor\s*\(\s*from\s*:\s*"([^"]+)"\s*\)\s*\)`)
	for _, match := range upToNextMajorRe.FindAllStringSubmatch(content, -1) {
		url := match[1]
		version := match[2]
		if name := normalizeSwiftURL(url); name != "" {
			packages = append(packages, pkg{Name: name, Version: version})
		}
	}

	// Match .package(url: "...", .upToNextMinor(from: "X.Y.Z"))
	upToNextMinorRe := regexp.MustCompile(`(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.upToNextMinor\s*\(\s*from\s*:\s*"([^"]+)"\s*\)\s*\)`)
	for _, match := range upToNextMinorRe.FindAllStringSubmatch(content, -1) {
		url := match[1]
		version := match[2]
		if name := normalizeSwiftURL(url); name != "" {
			packages = append(packages, pkg{Name: name, Version: version})
		}
	}

	return packages
}

// stripComments removes Swift-style comments from the content.
func stripComments(content string) string {
	// Remove multi-line comments: /* ... */
	result := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(content, "")
	// Remove single-line comments: //... (requires start-of-line or whitespace before //)
	result = regexp.MustCompile(`(?m)(^|\s)//.*$`).ReplaceAllString(result, "")
	return result
}

// normalizeSwiftURL converts a Swift package repository URL to the canonical
// package name used in PURL and OSV.dev SwiftURL ecosystem identifiers.
//
// Examples:
//
//	https://github.com/apple/swift-crypto.git → github.com/apple/swift-crypto
//	https://github.com/apple/swift-nio.git    → github.com/apple/swift-nio
func normalizeSwiftURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	// Strip scheme.
	loc := strings.TrimPrefix(rawURL, "https://")
	loc = strings.TrimPrefix(loc, "http://")
	// Strip .git suffix.
	loc = strings.TrimSuffix(loc, ".git")
	return loc
}
