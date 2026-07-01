// Copyright 2026 Google LLC
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

// Package nimblelock extracts nimble.lock files.
package nimblelock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "nim/nimblelock"
)

type nimbleLockPackage struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type nimbleLock struct {
	Packages map[string]nimbleLockPackage `json:"packages"`
	Version  int                          `json:"version"`
}

// Extractor extracts nimble.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches nimble.lock files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "nimble.lock"
}

// Extract extracts packages from a nimble.lock file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *nimbleLock

	if err := json.NewDecoder(input.Reader).Decode(&parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	if parsedLockfile == nil {
		return inventory.Inventory{}, errors.New("could not extract: decoded null JSON value")
	}

	names := make([]string, 0, len(parsedLockfile.Packages))
	for pkgName := range parsedLockfile.Packages {
		names = append(names, pkgName)
	}
	sort.Strings(names)

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))
	for _, pkgName := range names {
		pkg := parsedLockfile.Packages[pkgName]
		if pkg.Version == "" {
			continue
		}
		packages = append(packages, &extractor.Package{
			Name:     pkgName,
			Version:  pkg.Version,
			PURLType: purl.TypeNim,
			Location: extractor.LocationFromPath(input.Path),
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
