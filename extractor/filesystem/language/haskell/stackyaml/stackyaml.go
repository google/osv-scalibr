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

// Package stackyaml extracts Stack dependency declarations from stack.yaml manifests.
package stackyaml

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"gopkg.in/yaml.v3"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "haskell/stackyaml"
)

// stackYAML is the top-level structure of a stack.yaml file.
type stackYAML struct {
	ExtraDeps []any `yaml:"extra-deps"`
}

// Extractor extracts Stack dependency declarations from stack.yaml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches a stack.yaml.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "stack.yaml"
}

// Extract extracts Stack dependency declarations from stack.yaml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsed stackYAML
	if err := yaml.NewDecoder(input.Reader).Decode(&parsed); err != nil {
		// Empty files are valid YAML files with no content.
		if errors.Is(err, io.EOF) {
			return inventory.Inventory{Packages: make([]*extractor.Package, 0)}, nil
		}
		return inventory.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}
	if err := ctx.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
	}

	packages := make([]*extractor.Package, 0)
	for _, entry := range parsed.ExtraDeps {
		pkg := parseEntry(entry, input.Path)
		if pkg != nil {
			packages = append(packages, pkg)
		}
	}

	return inventory.Inventory{Packages: packages}, nil
}

func parseEntry(entry any, path string) *extractor.Package {
	str, ok := entry.(string)
	if !ok {
		return nil
	}

	name, version := splitNameVersion(str)
	if name == "" {
		return nil
	}

	pkg := &extractor.Package{
		Name:     name,
		PURLType: purl.TypeHaskell,
		Location: extractor.LocationFromPath(path),
	}
	if version != "" {
		pkg.Version = version
	}
	return pkg
}

// splitNameVersion splits a stack.yaml extra-deps string into package name and version.
// The version starts at the first hyphen where the part after it begins with a digit.
// Examples:
//
//	"foo-1.0"        -> name="foo", version="1.0"
//	"foo-bar-1.2.3"  -> name="foo-bar", version="1.2.3"
//	"foo-bar"        -> name="foo-bar", version="" (no version present)
//	"foo-1.0.0-beta" -> name="foo", version="1.0.0-beta"
//	"my-prerelease-1.0.0-alpha" -> name="my-prerelease", version="1.0.0-alpha"
func splitNameVersion(s string) (string, string) {
	for i := range len(s) {
		if s[i] == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			name := s[:i]
			version := s[i+1:]
			if name == "" || version == "" {
				return s, ""
			}
			return name, version
		}
	}
	return s, ""
}

var _ filesystem.Extractor = Extractor{}
