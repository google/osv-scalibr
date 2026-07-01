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

// Package conanfiletxt extracts inventory from conanfile.txt Conan manifests.
package conanfiletxt

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "cpp/conanfiletxt"
)

// conanReference represents a parsed Conan package reference.
// Format: name/version[@username[/channel]][#rrev]
type conanReference struct {
	Name    string
	Version string
}

// Extractor extracts Conan packages from conanfile.txt files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a conanfile.txt file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "conanfile.txt"
}

// Extract extracts dependencies from a conanfile.txt file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages := make([]*extractor.Package, 0)

	scanner := bufio.NewScanner(input.Reader)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section headers.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(line[1 : len(line)-1])
			continue
		}

		// Parse dependencies from relevant sections.
		if currentSection == "requires" || currentSection == "tool_requires" {
			ref := parseConanReference(line)
			if ref.Name != "" {
				group := "requires"
				if currentSection == "tool_requires" {
					group = "tool-requires"
				}
				packages = append(packages, &extractor.Package{
					Name:     ref.Name,
					Version:  ref.Version,
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath(input.Path),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{group},
					},
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// parseConanReference parses a Conan reference string into a conanReference.
// Format: name/version[@username[/channel]][#rrev][:pkgid[#prev]][%timestamp]
// We extract name and version only. References with no name are skipped.
func parseConanReference(ref string) conanReference {
	var result conanReference

	// Strip timestamp.
	if idx := strings.Index(ref, "%"); idx != -1 {
		ref = ref[:idx]
	}

	// Strip package ID and package revision.
	if idx := strings.Index(ref, ":"); idx != -1 {
		ref = ref[:idx]
	}

	// Strip recipe revision.
	if idx := strings.Index(ref, "#"); idx != -1 {
		ref = ref[:idx]
	}

	// Strip user/channel.
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}

	// Split name and version.
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 2 {
		result.Name = parts[0]
		result.Version = parts[1]
	} else {
		// If no slash, treat the whole thing as a name with no version.
		result.Name = ref
	}

	return result
}
