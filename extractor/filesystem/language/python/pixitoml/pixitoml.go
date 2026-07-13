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

// Package pixitoml extracts Pixi package dependencies from pixi.toml files.
package pixitoml

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
	// Name is the unique name of this extractor.
	Name = "python/pixitoml"
)

type pixiTomlFile struct {
	Dependencies     map[string]toml.Primitive    `toml:"dependencies"`
	PypiDependencies map[string]toml.Primitive    `toml:"pypi-dependencies"`
	Feature          map[string]pixiDependencySet `toml:"feature"`
	Target           map[string]pixiDependencySet `toml:"target"`
}

type pixiDepTable struct {
	Version string `toml:"version"`
}

type pixiDependencySet struct {
	Dependencies     map[string]toml.Primitive `toml:"dependencies"`
	PypiDependencies map[string]toml.Primitive `toml:"pypi-dependencies"`
}

// Extractor extracts Pixi packages from pixi.toml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a pixi.toml file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pixi.toml"
}

// Extract extracts packages from pixi.toml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var f pixiTomlFile
	md, err := toml.NewDecoder(input.Reader).Decode(&f)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	loc := extractor.LocationFromPath(input.Path)
	packages := make([]*extractor.Package, 0, len(f.Dependencies)+len(f.PypiDependencies))
	packages = appendPackages(packages, f.Dependencies, md, purl.TypeConda, loc)
	packages = appendPackages(packages, f.PypiDependencies, md, purl.TypePyPi, loc)
	for _, feature := range f.Feature {
		packages = appendPackages(packages, feature.Dependencies, md, purl.TypeConda, loc)
		packages = appendPackages(packages, feature.PypiDependencies, md, purl.TypePyPi, loc)
	}
	for _, target := range f.Target {
		packages = appendPackages(packages, target.Dependencies, md, purl.TypeConda, loc)
		packages = appendPackages(packages, target.PypiDependencies, md, purl.TypePyPi, loc)
	}

	return inventory.Inventory{Packages: packages}, nil
}

func appendPackages(
	packages []*extractor.Package,
	deps map[string]toml.Primitive,
	md toml.MetaData,
	purlType string,
	loc extractor.PackageLocation,
) []*extractor.Package {
	for name, prim := range deps {
		var version string
		// Try string first (e.g., python = ">=3.9")
		if err := md.PrimitiveDecode(prim, &version); err == nil {
			packages = append(packages, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purlType,
				Location: loc,
			})
			continue
		}

		// Try table with version field (e.g., numpy = { version = ">=1.24" })
		var dep pixiDepTable
		if err := md.PrimitiveDecode(prim, &dep); err == nil {
			packages = append(packages, &extractor.Package{
				Name:     name,
				Version:  dep.Version,
				PURLType: purlType,
				Location: loc,
			})
			continue
		}
		// Skip unparseable entries (e.g., git references, local paths)
	}
	return packages
}

var _ filesystem.Extractor = Extractor{}
