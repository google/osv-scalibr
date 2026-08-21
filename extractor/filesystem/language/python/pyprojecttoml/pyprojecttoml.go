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

// Package pyprojecttoml extracts dependencies from pyproject.toml files
// conforming to PEP 621. Specifically, it parses the standardized
// [project.dependencies] and [project.optional-dependencies] tables.
package pyprojecttoml

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pyprojecttoml"
)

// pyprojectFile represents the structure of a pyproject.toml file
type pyprojectFile struct {
	Project projectTable `toml:"project"`
}

// projectTable represents the [project] table as defined by PEP 621
type projectTable struct {
	Name                 string              `toml:"name"`
	Version              string              `toml:"version"`
	Dynamic              []string            `toml:"dynamic"`
	Dependencies         []string            `toml:"dependencies"`
	OptionalDependencies map[string][]string `toml:"optional-dependencies"`
}

// Extractor extracts Python packages from pyproject.toml files
type Extractor struct{}

var _ filesystem.Extractor = Extractor{}

// New returns a new instance of the extractor.
func New(*cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true only for files named exactly "pyproject.toml".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pyproject.toml"
}

// Extract extracts packages from the [project] table of a pyproject.toml file.
func (e Extractor) Extract(
	_ context.Context, input *filesystem.ScanInput,
) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	var f pyprojectFile
	if err := toml.Unmarshal(content, &f); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to parse pyproject.toml: %w", err)
	}

	if f.Project.Name == "" {
		// If no project.name is set, we assume that this is not a PEP-621 file.
		// Other tools use this file to store their configuration: poetry, uv, etc.
		return inventory.Inventory{}, nil
	}

	var pkgs []*extractor.Package
	pkgs = append(pkgs, &extractor.Package{
		Name:     f.Project.Name,
		Version:  f.Project.Version,
		PURLType: purl.TypePyPi,
		Location: extractor.LocationFromPath(input.Path),
		Metadata: &Metadata{
			HasDynamicDependencies: slices.Contains(f.Project.Dynamic, "dependencies"),
			Dependencies:           f.Project.Dependencies,
			OptionalDependencies:   f.Project.OptionalDependencies,
		},
	})

	return inventory.Inventory{Packages: pkgs}, nil
}
