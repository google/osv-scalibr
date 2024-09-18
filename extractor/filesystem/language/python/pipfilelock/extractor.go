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

// Package pipfilelock extracts Pipfile.lock files.
package pipfilelock

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/internal/pypipurl"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	"golang.org/x/exp/maps"
)

type pipenvPackage struct {
	Version string `json:"version"`
}

type pipenvLockFile struct {
	Packages    map[string]pipenvPackage `json:"default"`
	PackagesDev map[string]pipenvPackage `json:"develop"`
}

const pipenvEcosystem = "PyPI"

// Extractor extracts python packages from Pipfile.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "python/pipfilelock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Pipenv lockfile patterns.
func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "Pipfile.lock"
}

// Extract extracts packages from Pipfile.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *pipenvLockFile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	details := make(map[string]*extractor.Inventory)

	addPkgDetails(details, parsedLockfile.Packages, "")
	addPkgDetails(details, parsedLockfile.PackagesDev, "dev")

	for key := range details {
		details[key].Locations = []string{input.Path}
	}

	return maps.Values(details), nil
}

func addPkgDetails(details map[string]*extractor.Inventory, packages map[string]pipenvPackage, group string) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		// All pipenv package versions should be pinned with a ==
		// If it is not, this lockfile is not in the format we expect.
		if !strings.HasPrefix(pipenvPackage.Version, "==") || len(pipenvPackage.Version) < 3 {
			// Potentially log a warning here
			continue
		}

		version := pipenvPackage.Version[2:]

		// Because in the caller, prod packages are added first,
		// if it also exists in dev we don't want to add it to dev group
		if _, ok := details[name+"@"+version]; !ok {
			groupSlice := []string{}
			if group != "" {
				groupSlice = []string{group}
			}

			inv := &extractor.Inventory{
				Name:    name,
				Version: version,
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: groupSlice,
				},
			}

			details[name+"@"+version] = inv
		}
	}
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return pypipurl.MakePackageURL(i), nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns the OSV ecosystem ('PyPI') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return pipenvEcosystem, nil
}

var _ filesystem.Extractor = Extractor{}
