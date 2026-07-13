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

// Package composerjson extracts composer.json files for PHP projects.
package composerjson

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "php/composerjson"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by FileRequired.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// composerJSON represents the subset of a composer.json file needed for extraction.
type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// Extractor extracts packages from composer.json files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a composer.json extractor.
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

// FileRequired returns true if the specified file is named "composer.json".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "composer.json" {
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

// Extract parses and extracts dependency data from a composer.json file.
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
		return nil, fmt.Errorf("failed to read composer.json: %w", err)
	}

	var parsed composerJSON
	if err := json.Unmarshal(content, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	packages := []*extractor.Package{}

	for name, version := range parsed.Require {
		if pkg := buildPackage(input, name, version, nil); pkg != nil {
			packages = append(packages, pkg)
		}
	}

	for name, version := range parsed.RequireDev {
		if pkg := buildPackage(input, name, version, []string{"dev"}); pkg != nil {
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func buildPackage(input *filesystem.ScanInput, name, version string, groups []string) *extractor.Package {
	if !isValidPackageName(name) {
		return nil
	}

	v := simplifyVersion(version)
	if v == "" {
		return nil
	}

	return &extractor.Package{
		Name:     name,
		Version:  v,
		PURLType: purl.TypeComposer,
		Location: extractor.LocationFromPath(input.Path),
		Metadata: &osv.DepGroupMetadata{
			DepGroupVals: groups,
		},
	}
}

// isValidPackageName returns true if the name is a valid Composer package name
// and not a platform package (php, ext-*, lib-*).
func isValidPackageName(name string) bool {
	if name == "" {
		return false
	}

	// Skip platform packages.
	if name == "php" || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") || strings.HasPrefix(name, "php-") {
		return false
	}

	// Composer package names are vendor/package with a single slash.
	parts := strings.Split(name, "/")
	if len(parts) != 2 {
		return false
	}

	// Each part must be non-empty and contain only valid characters.
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.') {
				return false
			}
		}
	}

	return true
}

// simplifyVersion extracts a conservative minimum version from a Composer
// version constraint. It returns an empty string if the version should be
// skipped (wildcards, branch names, etc.).
func simplifyVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}

	// Skip wildcards and branch names.
	if v == "*" || strings.HasPrefix(v, "dev-") || strings.HasPrefix(v, "feature/") || strings.HasPrefix(v, "bugfix/") {
		return ""
	}

	// Skip inline aliases (e.g., "1.0 as 2.0").
	if strings.Contains(v, " as ") || strings.Contains(v, " AS ") {
		return ""
	}

	// Skip hyphen ranges (e.g., "1.0 - 2.0").
	if strings.Contains(v, " - ") {
		return ""
	}

	// Take the first part of an OR constraint.
	if idx := strings.Index(v, "||"); idx != -1 {
		v = strings.TrimSpace(v[:idx])
	}

	// Strip leading constraint operators.
	v = strings.TrimLeftFunc(v, func(r rune) bool {
		return r == '^' || r == '~' || r == '>' || r == '<' || r == '=' || r == '!' || r == ' ' || r == '*'
	})

	v = strings.TrimSpace(v)
	if v == "" || v == "*" {
		return ""
	}

	return v
}
