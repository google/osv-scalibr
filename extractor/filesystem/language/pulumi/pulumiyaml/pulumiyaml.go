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

// Package pulumiyaml extracts Pulumi Pulumi.yaml files.
package pulumiyaml

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"gopkg.in/yaml.v3"
)

const (
	// Name is the unique name of this extractor.
	Name = "pulumi/pulumiyaml"
)

// Extractor extracts Pulumi provider plugins from Pulumi.yaml files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a new Pulumi.yaml extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{maxFileSizeBytes: cfg.GetMaxFileSizeBytes()}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches Pulumi.yaml pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	base := filepath.Base(path)

	if base != "Pulumi.yaml" && base != "Pulumi.yml" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		return false
	}
	return true
}

// Extract extracts packages from Pulumi.yaml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := parsePulumiYAML(input.Path, input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error parsing Pulumi.yaml: %w", err)
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// pulumiPlugin represents a single plugin entry.
type pulumiPlugin struct {
	name    string
	version string
	line    int
}

func parsePulumiYAML(path string, r io.Reader) ([]*extractor.Package, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pulumi.yaml: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		log.Debugf("Pulumi.yaml %s yaml unmarshal failed: %v", path, err)
		return nil, nil // Gracefully skip malformed YAML
	}

	plugins := parsePlugins(&root)

	var pkgs []*extractor.Package
	for _, p := range plugins {
		if p.name == "" || p.version == "" {
			log.Debugf("skipping plugin block at line %d: missing name or version", p.line)
			continue
		}

		pkg := &extractor.Package{
			Name:     p.name,
			Version:  p.version,
			Location: extractor.LocationFromPathAndLine(path, p.line),
			PURLType: "", // No official Pulumi PURL type exists in the PURL spec.
		}
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func parsePlugins(root *yaml.Node) []pulumiPlugin {
	var plugins []pulumiPlugin

	if len(root.Content) == 0 {
		return plugins
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return plugins
	}

	var pluginsNode *yaml.Node
	for i := 0; i < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "plugins" {
			pluginsNode = doc.Content[i+1]
			break
		}
	}

	if pluginsNode == nil || pluginsNode.Kind != yaml.MappingNode {
		return plugins
	}

	// Walk children of plugins: providers, analyzers, etc.
	for i := 0; i < len(pluginsNode.Content); i += 2 {
		pluginTypeNode := pluginsNode.Content[i+1]
		if pluginTypeNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, entryNode := range pluginTypeNode.Content {
			if entryNode.Kind != yaml.MappingNode {
				continue
			}
			plugin := pulumiPlugin{line: entryNode.Line}
			for j := 0; j < len(entryNode.Content); j += 2 {
				key := entryNode.Content[j].Value
				val := entryNode.Content[j+1].Value
				switch strings.ToLower(key) {
				case "name":
					plugin.name = val
				case "version":
					plugin.version = val
				}
			}
			plugins = append(plugins, plugin)
		}
	}

	return plugins
}

var _ filesystem.Extractor = Extractor{}
