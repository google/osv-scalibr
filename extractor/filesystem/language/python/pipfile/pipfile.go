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

// Package pipfile extracts Pipfile dependencies.
package pipfile

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pipfile"
)

type pipfileDoc struct {
	Packages    map[string]any `toml:"packages"`
	DevPackages map[string]any `toml:"dev-packages"`
}

// Extractor extracts Python packages from Pipfile manifests.
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

// FileRequired returns true if the specified file matches Pipfile manifests.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Pipfile"
}

// Extract extracts packages from Pipfile files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if err := ctx.Err(); err != nil {
		return inventory.Inventory{}, err
	}
	var doc pipfileDoc
	if _, err := toml.NewDecoder(input.Reader).Decode(&doc); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	details := make(map[string]*extractor.Package)
	addPackages(details, doc.Packages, "", input.Path)
	addPackages(details, doc.DevPackages, "dev", input.Path)

	return inventory.Inventory{Packages: sortedPackages(details)}, nil
}

func addPackages(details map[string]*extractor.Package, packages map[string]any, group, path string) {
	for name, val := range packages {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}

		version := parseVersionSpec(val)
		if _, ok := details[name]; !ok {
			groupSlice := []string{}
			if group != "" {
				groupSlice = []string{group}
			}

			details[name] = &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypePyPi,
				Location: extractor.LocationFromPath(path),
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: groupSlice,
				},
			}
		}
	}
}

func parseVersionSpec(val any) string {
	var spec string
	switch v := val.(type) {
	case string:
		spec = strings.TrimSpace(v)
	case map[string]any:
		if ver, ok := v["version"].(string); ok {
			spec = strings.TrimSpace(ver)
		}
	}

	if spec == "" || spec == "*" {
		return ""
	}

	// Strip common Pipenv/TOML version comparison prefixes if present.
	for _, prefix := range []string{"==", ">=", "<=", "~=", ">", "<", "="} {
		if after, ok := strings.CutPrefix(spec, prefix); ok {
			return strings.TrimSpace(after)
		}
	}
	return spec
}

func sortedPackages(packages map[string]*extractor.Package) []*extractor.Package {
	pkgs := slices.Collect(maps.Values(packages))
	slices.SortFunc(pkgs, func(a, b *extractor.Package) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return pkgs
}

var _ filesystem.Extractor = Extractor{}
