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

// Package chartlock extracts Helm Chart.lock files.
package chartlock

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

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
	Name = "helm/chartlock"
)

// Extractor extracts Helm chart dependencies from Chart.lock files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a new Chart.lock extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{maxFileSizeBytes: cfg.GetMaxFileSizeBytes()}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches Chart.lock pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if filepath.Base(path) != "Chart.lock" {
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

// Extract extracts packages from Chart.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := parseChartLock(input.Path, input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error parsing Chart.lock: %w", err)
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// chartDependency represents a single dependency entry in Chart.lock.
type chartDependency struct {
	name       string
	version    string
	repository string
	line       int
}

func parseChartLock(path string, r io.Reader) ([]*extractor.Package, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read Chart.lock: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		log.Debugf("Chart.lock %s yaml unmarshal failed: %v", path, err)
		return nil, nil // Gracefully skip malformed YAML
	}

	deps := parseDependencies(&root)

	var pkgs []*extractor.Package
	for _, d := range deps {
		if d.name == "" || d.version == "" {
			log.Debugf("skipping dependency block at line %d: missing name or version", d.line)
			continue
		}

		pkg := &extractor.Package{
			Name:     d.name,
			Version:  d.version,
			Location: extractor.LocationFromPathAndLine(path, d.line),
			PURLType: "", // No official Helm PURL type exists in the PURL spec.
		}
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func parseDependencies(root *yaml.Node) []chartDependency {
	var deps []chartDependency

	if len(root.Content) == 0 {
		return deps
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return deps
	}

	var depsNode *yaml.Node
	for i := 0; i < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "dependencies" {
			depsNode = doc.Content[i+1]
			break
		}
	}

	if depsNode == nil || depsNode.Kind != yaml.SequenceNode {
		return deps
	}

	for _, depNode := range depsNode.Content {
		if depNode.Kind != yaml.MappingNode {
			continue
		}
		dep := chartDependency{line: depNode.Line}
		for i := 0; i < len(depNode.Content); i += 2 {
			key := depNode.Content[i].Value
			val := depNode.Content[i+1].Value
			switch key {
			case "name":
				dep.name = val
			case "version":
				dep.version = val
			case "repository":
				dep.repository = val
			}
		}
		deps = append(deps, dep)
	}

	return deps
}

var _ filesystem.Extractor = Extractor{}
