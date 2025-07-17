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

// Package cargolock extracts Cargo.lock files for rust projects
package cargolock

import (
	"context"
	"fmt"
	"path/filepath"

	"encoding/json"
	"net/http"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "rust/cargolock"
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

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches Cargo lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Cargo.lock"
}

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Extract extracts packages from Cargo.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *cargoLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		isYanked, err := isYanked(ctx, lockPackage.Name, lockPackage.Version)
		if err != nil {
			isYanked = false // Non-fatal
		}

		packages = append(packages, &extractor.Package{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			PURLType:  purl.TypeCargo,
			Locations: []string{input.Path},
			Yanked:    isYanked,
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

func isYanked(ctx context.Context, crate, version string) (bool, error) {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s", crate, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to fetch yanked info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var data struct {
		Version struct {
			Yanked bool `json:"yanked"`
		} `json:"version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false, fmt.Errorf("failed to decode crates.io response: %w", err)
	}

	return data.Version.Yanked, nil
}

var _ filesystem.Extractor = Extractor{}
