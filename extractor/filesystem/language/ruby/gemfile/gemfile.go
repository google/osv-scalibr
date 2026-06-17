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

// Package gemfile extracts Ruby packages from Gemfile dependency declarations.
package gemfile

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "ruby/gemfile"
	// MaxGemfileSize is the maximum size of a Gemfile we will parse (1 MB).
	MaxGemfileSize = 1024 * 1024
)

var (
	// gemRegex matches: gem "name" [, "version"] [, options...]
	gemRegex = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*([^\s].*?))?\s*$`)
	// versionRegex extracts the first quoted string from a comma-separated value list.
	versionRegex = regexp.MustCompile(`['"]([^'"]+)['"]`)
)

// Extractor extracts Ruby packages from Gemfile dependency declarations.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file is a Gemfile.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Gemfile"
}

// Extract extracts Ruby packages from the Gemfile.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info != nil && input.Info.Size() > MaxGemfileSize {
		return inventory.Inventory{}, fmt.Errorf("%s: file size %d exceeds maximum %d", Name, input.Info.Size(), MaxGemfileSize)
	}

	packages, err := ParseGemfile(ctx, input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	for _, pkg := range packages {
		pkg.Location = extractor.LocationFromPath(input.Path)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// ParseGemfile parses a Gemfile and extracts dependency names.
func ParseGemfile(ctx context.Context, r io.Reader) ([]*extractor.Package, error) {
	scanner := bufio.NewScanner(r)
	var packages []*extractor.Package

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s halted due to context error: %w", Name, err)
		}

		line := stripInlineComment(scanner.Text())
		trimmed := strings.TrimSpace(line)

		// Skip empty lines, comments, and non-gem lines.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		match := gemRegex.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		name := match[1]
		if name == "" {
			continue
		}

		var version string
		if len(match) > 2 && match[2] != "" {
			rest := match[2]
			trimmedRest := strings.TrimSpace(rest)
			// If the first non-whitespace character is a quote, it's a version constraint.
			if strings.HasPrefix(trimmedRest, `"`) || strings.HasPrefix(trimmedRest, `'`) {
				// Extract first quoted string as version constraint.
				vMatch := versionRegex.FindStringSubmatch(rest)
				if vMatch != nil {
					version = vMatch[1]
				}
			}
		}

		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeGem,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

func stripInlineComment(line string) string {
	var quote rune
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if quote != 0 {
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' {
			return strings.TrimRight(line[:i], " \t")
		}
	}
	return line
}

var _ filesystem.Extractor = Extractor{}
