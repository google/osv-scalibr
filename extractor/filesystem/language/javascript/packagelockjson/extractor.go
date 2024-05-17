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

// Package packagelockjson extracts package-lock.json files.
package packagelockjson

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/purl"
)

// Extractor extracts javascript packages from package-lock.json files.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return "javascript/packagelockjson" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches javascript Metadata file
// patterns.
func (e Extractor) FileRequired(path string, _ fs.FileMode) bool {
	return filepath.Base(path) == "package-lock.json"
}

// Extract extracts packages from package-lock.json files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	osve := lockfile.NpmLockExtractor{}
	osvpkgs, err := osve.Extract(osv.WrapInput(input))
	if err != nil {
		return nil, fmt.Errorf("NpmLockExtractor.Extract(): %w", err)
	}

	r := []*extractor.Inventory{}
	for _, p := range osvpkgs {
		r = append(r, &extractor.Inventory{
			Name:      p.Name,
			Version:   p.Version,
			Locations: []string{input.Path},
		})
	}

	return r, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypeNPM,
		Name:    strings.ToLower(i.Name),
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
