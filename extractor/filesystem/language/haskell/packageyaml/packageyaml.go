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

// Package packageyaml extracts inventory from package.yaml Haskell manifests.
package packageyaml

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

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
	Name = "haskell/packageyaml"
)

// Extractor extracts Haskell packages from package.yaml files.
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

// FileRequired returns true if the specified file is a package.yaml file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "package.yaml"
}

// Extract extracts dependencies from a package.yaml file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return inventory.Inventory{}, fmt.Errorf("yaml.Unmarshal(%s): %w", input.Path, err)
	}

	packages := make([]*extractor.Package, 0)
	seen := map[string]bool{}
	collectDependencies(&doc, input.Path, seen, &packages)

	return inventory.Inventory{Packages: packages}, nil
}

func collectDependencies(node *yaml.Node, path string, seen map[string]bool, packages *[]*extractor.Package) {
	if node == nil {
		return
	}
	if node.Kind != yaml.MappingNode {
		for _, child := range node.Content {
			collectDependencies(child, path, seen, packages)
		}
		return
	}

	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		if key.Value == "dependencies" {
			parseDependencyNode(value, path, seen, packages)
			continue
		}
		collectDependencies(value, path, seen, packages)
	}
}

func parseDependencyNode(node *yaml.Node, path string, seen map[string]bool, packages *[]*extractor.Package) {
	switch node.Kind {
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				name, version := parseDependencyString(item.Value)
				addPackage(name, version, path, seen, packages)
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			name := node.Content[i].Value
			version := ""
			if node.Content[i+1].Kind == yaml.ScalarNode {
				version = strings.TrimSpace(node.Content[i+1].Value)
			}
			addPackage(name, version, path, seen, packages)
		}
	}
}

func addPackage(name, version, path string, seen map[string]bool, packages *[]*extractor.Package) {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" {
		return
	}
	key := name + "\x00" + version
	if seen[key] {
		return
	}
	seen[key] = true
	*packages = append(*packages, &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeHaskell,
		Location: extractor.LocationFromPath(path),
	})
}

// parseDependencyString parses a dependency string like "base >= 4.14" or "aeson".
// Returns the package name and version constraint.
func parseDependencyString(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}

	// Split on first space to separate name from version constraint.
	idx := strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
	if idx == -1 {
		return s, ""
	}

	name := strings.TrimSpace(s[:idx])
	version := strings.TrimSpace(s[idx:])

	return name, version
}
