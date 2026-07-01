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

// Package pubspecyaml extracts Dart pubspec.yaml manifest files.
package pubspecyaml

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"gopkg.in/yaml.v3"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "dart/pubspecyaml"
)

// Extractor extracts Dart packages from pubspec.yaml manifest files.
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

// FileRequired returns true if the specified file is a pubspec.yaml
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pubspec.yaml"
}

// Extract extracts Dart packages from pubspec.yaml files passed through the input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedFile pubspecYAML
	if err := yaml.NewDecoder(input.Reader).Decode(&parsedFile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0)

	// Extract dependencies
	for name, val := range parsedFile.Dependencies {
		pkg := parsePackage(name, val, false)
		if pkg != nil {
			pkg.Location = extractor.LocationFromPath(input.Path)
			packages = append(packages, pkg)
		}
	}

	// Extract dev_dependencies
	for name, val := range parsedFile.DevDependencies {
		pkg := parsePackage(name, val, true)
		if pkg != nil {
			pkg.Location = extractor.LocationFromPath(input.Path)
			packages = append(packages, pkg)
		}
	}

	// Extract dependency_overrides (not dev dependencies)
	for name, val := range parsedFile.DependencyOverrides {
		pkg := parsePackage(name, val, false)
		if pkg != nil {
			pkg.Location = extractor.LocationFromPath(input.Path)
			packages = append(packages, pkg)
		}
	}

	return inventory.Inventory{Packages: packages}, nil
}

// pubspecYAML represents the structure of a pubspec.yaml file.
type pubspecYAML struct {
	Dependencies        map[string]any `yaml:"dependencies"`
	DevDependencies     map[string]any `yaml:"dev_dependencies"`
	DependencyOverrides map[string]any `yaml:"dependency_overrides"`
}

// parsePackage converts a pubspec.yaml dependency entry into an extractor.Package.
// It returns nil if the entry is an SDK dependency (e.g. flutter: sdk: flutter) or
// a local/git dependency without a version.
func parsePackage(name string, val any, isDev bool) *extractor.Package {
	if name == "flutter" {
		return nil
	}

	var version string
	switch v := val.(type) {
	case string:
		version = v
	case map[string]any:
		if vv, ok := v["version"].(string); ok {
			version = vv
		}
	}

	if version == "" {
		return nil
	}

	pkg := &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypePub,
		Metadata: &osv.DepGroupMetadata{},
	}
	if isDev {
		pkg.Metadata = &osv.DepGroupMetadata{DepGroupVals: []string{"dev"}}
	}
	return pkg
}

var _ filesystem.Extractor = Extractor{}
