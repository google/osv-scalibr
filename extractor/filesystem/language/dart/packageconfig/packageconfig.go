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

// Package packageconfig extracts Dart .dart_tool/package_config.json files.
package packageconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "dart/packageconfig"

	// packageConfigFilename is the filename of the Dart package configuration file.
	packageConfigFilename = "package_config.json"

	// packageConfigDir is the directory the file is expected to live in.
	packageConfigDir = ".dart_tool"
)

// packageConfigPackage is a single package entry in package_config.json.
// The version field is optional and may be missing or empty; rootUri is not
// followed on disk.
type packageConfigPackage struct {
	Name    string `json:"name"`
	RootURI string `json:"rootUri"`
	Version string `json:"version"`
}

// packageConfigFile is the top-level package_config.json structure.
// See https://dart.dev/go/package-config.
type packageConfigFile struct {
	ConfigVersion int                    `json:"configVersion"`
	Packages      []packageConfigPackage `json:"packages"`
}

// Extractor extracts Dart .dart_tool/package_config.json files.
type Extractor struct{}

var _ filesystem.Extractor = Extractor{}

// New returns a new instance of this extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a .dart_tool/package_config.json file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != packageConfigFilename {
		return false
	}
	// The file must live inside a .dart_tool directory. Match the immediate
	// parent directory name so that unrelated package_config.json-like files
	// (e.g. mypkg/package_config.json) are not picked up.
	parent := filepath.Base(filepath.Dir(path))
	return parent == packageConfigDir
}

// Extract extracts Dart packages from .dart_tool/package_config.json files
// passed through the input. rootUri values are not followed on disk.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsed packageConfigFile
	if err := json.NewDecoder(input.Reader).Decode(&parsed); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsed.Packages))
	for _, pkg := range parsed.Packages {
		name := strings.TrimSpace(pkg.Name)
		if name == "" {
			continue
		}

		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  strings.TrimSpace(pkg.Version),
			PURLType: purl.TypePub,
			Location: extractor.LocationFromPath(input.Path),
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}
