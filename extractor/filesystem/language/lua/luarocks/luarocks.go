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

// Package luarocks extracts .rockspec files from Lua modules.
package luarocks

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "lua/luarocks"
)

// Extractor extracts Lua module info from .rockspec files.
type Extractor struct{}

// New returns a lua luarocks extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired return true if the specified file matched the .rockspec file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if !strings.HasSuffix(path, ".rockspec") {
		return false
	}

	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))

	// Check if there are enough parts because a regular path should contain at least /rocks-5.x/../../x.rockspec
	if len(parts) < 4 {
		// Path is too short to have a 4rd parent
		return false
	}
	// 3rd parent from the file
	rocksParent := parts[len(parts)-4]

	// check parents folder for the following path convention: ../rocks-5.x/../../x.rockspec
	if !strings.HasPrefix(rocksParent, "rocks-") {
		return false
	}
	return true
}

// Extract extracts Package info from .rockspec file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs := e.extractFromPath(input.Path)
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) extractFromPath(path string) []*extractor.Package {
	// Split path into components
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))

	if len(parts) >= 4 && strings.HasPrefix(parts[len(parts)-4], "rocks-") {
		// 2nd parent = module name, 1st parent = version
		module := parts[len(parts)-3]
		version := parts[len(parts)-2]
		pkg := &extractor.Package{
			Name:      module,
			Version:   version,
			PURLType:  purl.TypeLua,
			Locations: []string{path},
		}
		return []*extractor.Package{pkg}
	}

	log.Errorf("failed to extract package version from the following path : %s", path)
	return nil
}
