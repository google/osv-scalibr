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

// Package bunlock extracts bun.lock files
package bunlock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/tidwall/jsonc"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/bunlock"
)

type bunLockfile struct {
	Version  int              `json:"lockfileVersion"`
	Packages map[string][]any `json:"packages"`
}

// Extractor extracts npm packages from bun.lock files.
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

// FileRequired returns true if the specified file matches bun lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "bun.lock" {
		return false
	}
	// Skip lockfiles inside node_modules directories since the packages they list aren't
	// necessarily installed by the root project. We instead use the more specific top-level
	// lockfile for the root project dependencies.
	dir := filepath.ToSlash(filepath.Dir(path))
	return !slices.Contains(strings.Split(dir, "/"), "node_modules")
}

// structurePackageDetails returns the name, version, and commit of a package
// specified as a tuple in a bun.lock
func structurePackageDetails(pkgs []any) (string, string, string, error) {
	if len(pkgs) == 0 {
		return "", "", "", errors.New("empty package tuple")
	}

	str, ok := pkgs[0].(string)

	if !ok {
		return "", "", "", errors.New("first element of package tuple is not a string")
	}

	str, isScoped := strings.CutPrefix(str, "@")
	name, version, _ := strings.Cut(str, "@")

	if isScoped {
		name = "@" + name
	}

	version, commit, _ := strings.Cut(version, "#")

	// bun.lock does not track both the commit and version,
	// so if we have a commit then we don't have a version
	if commit != "" {
		version = ""
	}

	// file dependencies do not have a semantic version recorded
	if strings.HasPrefix(version, "file:") {
		version = ""
	}

	return name, version, commit, nil
}

// Extract extracts packages from bun.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *bunLockfile

	b, err := io.ReadAll(input.Reader)

	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	if err := json.Unmarshal(jsonc.ToJSON(b), &parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))

	var errs []error

	for key, pkg := range parsedLockfile.Packages {
		name, version, commit, err := structurePackageDetails(pkg)

		if err != nil {
			errs = append(errs, fmt.Errorf("could not extract '%s': %w", key, err))

			continue
		}

		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeNPM,
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
			},
			Metadata: osv.DepGroupMetadata{
				DepGroupVals: []string{},
			},
			Locations: []string{input.Path},
		})
	}

	return inventory.Inventory{Packages: packages}, errors.Join(errs...)
}
