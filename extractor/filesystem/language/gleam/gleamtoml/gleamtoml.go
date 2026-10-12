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

// Package gleamtoml extracts gleam.toml files for Gleam projects.
package gleamtoml

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the name of the Extractor.
	Name = "gleam/gleamtoml"
)

type gleamTomlFile struct {
	Dependencies    map[string]toml.Primitive `toml:"dependencies"`
	DevDependencies map[string]toml.Primitive `toml:"dev-dependencies"`
}

// gleamDep represents a non-string (table) dependency entry.
type gleamDep struct {
	Version string `toml:"version"`
	Git     string `toml:"git"`
	Ref     string `toml:"ref"`
	Path    string `toml:"path"`
}

// Extractor extracts Gleam packages from gleam.toml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a gleam.toml file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "gleam.toml"
}

// Extract extracts packages from gleam.toml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var f gleamTomlFile
	md, err := toml.NewDecoder(input.Reader).Decode(&f)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	loc := extractor.LocationFromPath(input.Path)
	packages := make([]*extractor.Package, 0, len(f.Dependencies)+len(f.DevDependencies))

	packages, err = appendPackages(ctx, packages, f.Dependencies, md, loc)
	if err != nil {
		return inventory.Inventory{Packages: packages}, err
	}
	packages, err = appendPackages(ctx, packages, f.DevDependencies, md, loc)
	if err != nil {
		return inventory.Inventory{Packages: packages}, err
	}

	return inventory.Inventory{Packages: packages}, nil
}

func appendPackages(
	ctx context.Context,
	packages []*extractor.Package,
	deps map[string]toml.Primitive,
	md toml.MetaData,
	loc extractor.PackageLocation,
) ([]*extractor.Package, error) {
	for name, prim := range deps {
		if err := ctx.Err(); err != nil {
			return packages, fmt.Errorf("gleam/gleamtoml halted due to context error: %w", err)
		}

		// Try string first (e.g. gleam_stdlib = ">= 0.34.0 and < 2.0.0")
		var version string
		if err := md.PrimitiveDecode(prim, &version); err == nil {
			packages = append(packages, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeHex,
				Location: loc,
			})
			continue
		}

		var dep gleamDep
		if err := md.PrimitiveDecode(prim, &dep); err != nil {
			return packages, fmt.Errorf("gleam/gleamtoml: could not decode dependency %q: %w", name, err)
		}

		// Skip local path dependencies.
		if dep.Path != "" {
			continue
		}

		// Git dependency: populate SourceCode.
		if dep.Git != "" {
			packages = append(packages, &extractor.Package{
				Name:     name,
				Version:  dep.Version,
				PURLType: purl.TypeHex,
				Location: loc,
				SourceCode: &extractor.SourceCodeIdentifier{
					Repo:   dep.Git,
					Commit: dep.Ref,
				},
			})
		}

		// As far as I know, it is invalid to use the table format for only specifying version,
		// but just in case, we'll handle it here.
		if dep.Version != "" {
			packages = append(packages, &extractor.Package{
				Name:     name,
				Version:  dep.Version,
				PURLType: purl.TypeHex,
				Location: loc,
			})
		}
	}
	return packages, nil
}

var _ filesystem.Extractor = Extractor{}
