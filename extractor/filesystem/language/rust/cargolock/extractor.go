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

// Package cargolock extracts Cargo.lock files for rust projects
package cargolock

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type cargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type cargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []cargoLockPackage `toml:"package"`
}

// Extractor extracts crates.io packages from Cargo.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "rust/Cargolock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches Cargo lockfile patterns.
func (e Extractor) FileRequired(path string, _ fs.FileInfo) bool {
	return filepath.Base(path) == "Cargo.lock"
}

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Extract extracts packages from Cargo.lock files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *cargoLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		packages = append(packages, &extractor.Inventory{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Locations: []string{input.Path},
		})
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypeCargo,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(_ *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns the OSV ecosystem ('crates.io') of the software extracted by this extractor.
func (e Extractor) Ecosystem(_ *extractor.Inventory) string {
	return "crates.io"
}

var _ filesystem.Extractor = Extractor{}
