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

// Package composerlock extracts composer.lock files.
package composerlock

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "php/composerlock"
)

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Reference string `json:"reference"`
	} `json:"dist"`
}

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

// Extractor extracts composer.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches composer.lock files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "composer.lock"
}

func buildPackage(input *filesystem.ScanInput, pkg composerPackage, groups []string) *extractor.Package {
	commit := pkg.Dist.Reference

	// a dot means the reference is likely a tag, rather than a commit
	if strings.Contains(commit, ".") {
		commit = ""
	}

	return &extractor.Package{
		Name:      pkg.Name,
		Version:   pkg.Version,
		PURLType:  purl.TypeComposer,
		Locations: []string{input.Path},
		SourceCode: &extractor.SourceCodeIdentifier{
			Commit: commit,
		},
		Metadata: osv.DepGroupMetadata{
			DepGroupVals: groups,
		},
	}
}

// Extract extracts packages from a composer.lock file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *composerLock

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make(
		[]*extractor.Package,
		0,
		// len cannot return negative numbers, but the types can't reflect that
		uint64(len(parsedLockfile.Packages))+uint64(len(parsedLockfile.PackagesDev)),
	)

	for _, pkg := range parsedLockfile.Packages {
		packages = append(packages, buildPackage(input, pkg, []string{}))
	}

	for _, pkg := range parsedLockfile.PackagesDev {
		packages = append(packages, buildPackage(input, pkg, []string{"dev"}))
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
