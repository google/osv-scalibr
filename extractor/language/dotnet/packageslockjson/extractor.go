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

// Package packageslockjson extracts packages.lock.json files.
package packageslockjson

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "dotnet/packageslockjson"
)

// Extractor extracts packages from inside a packages.lock.json.
type Extractor struct{}

// PackagesLockJSON represents the `packages.lock.json` file generated from
// running `dotnet restore --use-lock-file`.
// The schema path we care about is:
// "dependencies" -> target framework moniker -> package name -> package info
type PackagesLockJSON struct {
	Dependencies map[string]map[string]PackageInfo `json:"dependencies"`
}

// PackageInfo represents a single package's info, including its resolved
// version, and its dependencies
type PackageInfo struct {
	// Resolved is the resolved version for this dependency.
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file is marked executable.
func (e Extractor) FileRequired(path string, mode fs.FileMode) bool {
	return filepath.Base(path) == "packages.lock.json"
}

// Extract returns a list of dependencies in a packages.lock.json file.
func (e Extractor) Extract(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	p, err := Parse(input.Reader)
	if err != nil {
		return nil, err
	}
	var res []*extractor.Inventory
	for _, pkgs := range p.Dependencies {
		for pkgName, info := range pkgs {
			inv := &extractor.Inventory{
				Name:    pkgName,
				Version: info.Resolved,
				Locations: []string{
					input.Path,
				},
				Extractor: e.Name(),
			}
			res = append(res, inv)
		}
	}

	return res, nil
}

// Parse returns a struct representing the structure of a .NET project's
// packages.lock.json file.
func Parse(r io.Reader) (PackagesLockJSON, error) {
	dec := json.NewDecoder(r)
	var p PackagesLockJSON
	if err := dec.Decode(&p); err != nil {
		return PackagesLockJSON{}, fmt.Errorf("failed to decode packages.lock.json file: %w", err)
	}

	return p, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypeNuget,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
