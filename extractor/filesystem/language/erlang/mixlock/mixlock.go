// Copyright 2024 Google LLC
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

// Package mixlock extracts erlang mix.lock files.
package mixlock

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

var (
	// "name": {:git, repo, "commit-hash", <other comma-separated values> },
	gitDependencyLineRe = regexp.MustCompile(`^ +"([^"]+)": \{:git, +"([^,]+)", +\"([^,]+)\",.+$`)
	// "name": {source, name, "version", "commit-hash", <other comma-separated values> },
	regularDependencyLineRe = regexp.MustCompile(`^ +"([^"]+)": \{([^,]+), +([^,]+), +\"([^,]+)\", +\"([^,]+)\",.+$`)
)

// Extractor extracts erlang mix.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "erlang/mixlock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a mix.lock file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "mix.lock"
}

// Extract extracts packages from erlang mix.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)

	var packages []*extractor.Inventory

	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		line := scanner.Text()

		var name, version, commit string

		match := gitDependencyLineRe.FindStringSubmatch(line)
		if match != nil {
			// This is a git dependency line, doesn't have a version info.
			if len(match) < 4 {
				log.Errorf("invalid mix.lock dependency line %q", line)
				continue
			}
			name = match[1]
			commit = match[3]
		} else {
			// This is a regular dependency line with both version and commit info.
			match = regularDependencyLineRe.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			if len(match) < 6 {
				log.Errorf("invalid mix.lock dependency line %q", line)
				continue
			}
			name = match[1]
			version = match[4]
			commit = match[5]
		}

		packages = append(packages, &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{input.Path},
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
			},
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while scanning %s: %w", input.Path, err)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeHex,
		Name:    strings.ToLower(i.Name),
		Version: i.Version,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return "Hex"
}

var _ filesystem.Extractor = Extractor{}
