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

// Package renvlock extracts renv.lock files.
package renvlock

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type renvPackage struct {
	Package    string `json:"Package"`
	Version    string `json:"Version"`
	Repository string `json:"Repository"`
}

type renvLockfile struct {
	Packages map[string]renvPackage `json:"Packages"`
}

// Extractor extracts CRAN packages from renv.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "r/renvlock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches renv lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "renv.lock"
}

// Extract extracts packages from renv.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *renvLockfile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(parsedLockfile.Packages))

	for _, pkg := range parsedLockfile.Packages {
		// currently we only support CRAN
		if pkg.Repository != "CRAN" {
			continue
		}

		packages = append(packages, &extractor.Inventory{
			Name:      pkg.Package,
			Version:   pkg.Version,
			Locations: []string{input.Path},
		})
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeCran,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Ecosystem returns the OSV ecosystem ('CRAN') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return "CRAN"
}

var _ filesystem.Extractor = Extractor{}
