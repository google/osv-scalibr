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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cargotoml extracts Cargo.toml files for rust projects
package cargotoml

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/BurntSushi/toml"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the name of the Extractor.
	Name = "rust/cargotoml"
)

var shaPattern = regexp.MustCompile("^[0-9a-f]{40}$")

type cargoTomlDependency struct {
	Version string
	Git     string
	Rev     string
}

// UnmarshalTOML parses a dependency from a Cargo.toml file.
//
// Dependencies in Cargo.toml can be defined as simple strings (e.g., version)
// or as more complex objects (e.g., with version, path, etc.)
//
// in case both the Version and Git/Path are specified the version should be considered
// the source of truth
func (v *cargoTomlDependency) UnmarshalTOML(data any) error {
	getString := func(m map[string]any, key string) (string, error) {
		v, ok := m[key]
		if !ok {
			// if the key does not exists leave the string value empty
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			// if the key exists but the type is wrong return an error
			return "", fmt.Errorf("invalid type for key %q: expected string, got %T", key, v)
		}
		return s, nil
	}

	switch data := data.(type) {
	case string:
		// if the type is string then the data is version
		v.Version = data
		return nil
	case map[string]any:
		var err error
		if v.Version, err = getString(data, "version"); err != nil {
			return err
		}
		if v.Git, err = getString(data, "git"); err != nil {
			return err
		}
		if v.Rev, err = getString(data, "rev"); err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid format for Cargo.toml dependency")
	}
}

// IsCommitSpecified checks if the dependency specifies a Git commit.
func (v *cargoTomlDependency) IsCommitSpecified() bool {
	return v.Git != "" && shaPattern.MatchString(v.Rev)
}

type cargoTomlPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type cargoTomlFile struct {
	Package      cargoTomlPackage               `toml:"package"`
	Dependencies map[string]cargoTomlDependency `toml:"dependencies"`
}

// Extractor extracts crates.io packages from Cargo.toml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches Cargo toml file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Cargo.toml"
}

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Extract extracts packages from Cargo.toml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedTomlFile cargoTomlFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedTomlFile)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsedTomlFile.Dependencies)+1)

	packages = append(packages, &extractor.Package{
		Name:      parsedTomlFile.Package.Name,
		Version:   parsedTomlFile.Package.Version,
		PURLType:  purl.TypeCargo,
		Locations: []string{input.Path},
	})

	for name, dependency := range parsedTomlFile.Dependencies {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{Packages: packages}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		var srcCode *extractor.SourceCodeIdentifier
		if dependency.IsCommitSpecified() {
			srcCode = &extractor.SourceCodeIdentifier{
				Repo:   dependency.Git,
				Commit: dependency.Rev,
			}
		}

		// Skip dependencies that have no version and no useful source code information
		if dependency.Version == "" && srcCode == nil {
			continue
		}

		packages = append(packages, &extractor.Package{
			Name:       name,
			Version:    dependency.Version,
			PURLType:   purl.TypeCargo,
			Locations:  []string{input.Path},
			SourceCode: srcCode,
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
