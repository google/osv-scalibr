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
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
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
	getString := func(m map[string]any, key string) string {
		v, ok := m[key]
		if !ok {
			return ""
		}
		s, _ := v.(string)
		return s
	}

	switch data := data.(type) {
	case string:
		// if the type is string then the data is version
		v.Version = data
		return nil
	case map[string]any:
		*v = cargoTomlDependency{
			Version: getString(data, "version"),
			Git:     getString(data, "git"),
			Rev:     getString(data, "rev"),
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

// Name of the extractor
func (e Extractor) Name() string { return "rust/Cargotoml" }

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
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedTomlFile cargoTomlFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedTomlFile)
	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(parsedTomlFile.Dependencies)+1)

	packages = append(packages, &extractor.Inventory{
		Name:      parsedTomlFile.Package.Name,
		Version:   parsedTomlFile.Package.Version,
		Locations: []string{input.Path},
	})

	for name, dependency := range parsedTomlFile.Dependencies {
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

		packages = append(packages, &extractor.Inventory{
			Name:       name,
			Version:    dependency.Version,
			Locations:  []string{input.Path},
			SourceCode: srcCode,
		})
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeCargo,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Ecosystem returns the OSV ecosystem ('crates.io') of the software extracted by this extractor.
func (e Extractor) Ecosystem(_ *extractor.Inventory) string {
	return "crates.io"
}

var _ filesystem.Extractor = Extractor{}
