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

// Package packageconfig extracts Dart package_config.json files.
package packageconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"

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
)

// We want to match strings like package_name-version, optionally with more parts, but usually standard semantic versions.
// We'll extract anything that looks like a version suffix from the rootUri, when there is one.
var versionRe = regexp.MustCompile(`^.*?-([0-9]+\.[0-9]+\.[0-9]+.*)$`)

type packageConfigPackage struct {
	Name            string `json:"name"`
	RootURI         string `json:"rootUri"`
	PackageURI      string `json:"packageUri,omitempty"`
	LanguageVersion string `json:"languageVersion,omitempty"`
}

type packageConfigFile struct {
	ConfigVersion int                    `json:"configVersion"`
	Packages      []packageConfigPackage `json:"packages,omitempty"`
}

// Extractor extracts Dart packages from package_config.json files.
type Extractor struct{}

// New returns a new instance of this Extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a package_config.json
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "package_config.json"
}

// Extract extracts Dart packages from package_config.json files passed through the input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedConfig packageConfigFile
	if err := json.NewDecoder(input.Reader).Decode(&parsedConfig); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsedConfig.Packages))

	for _, pkg := range parsedConfig.Packages {
		if pkg.Name == "" {
			continue
		}

		version := ""
		if pkg.RootURI != "" {
			// To avoid matching hyphens in path directories, we'll only match the final path component.
			baseURI := filepath.Base(pkg.RootURI)

			matches := versionRe.FindStringSubmatch(baseURI)
			if len(matches) > 1 {
				version = matches[1]
			}
		}

		pkgDetails := &extractor.Package{
			Name:     pkg.Name,
			Version:  version,
			PURLType: purl.TypePub,
		}

		packages = append(packages, pkgDetails)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
