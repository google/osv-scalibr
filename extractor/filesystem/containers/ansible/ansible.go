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

// Package ansible extracts container image references from Ansible playbook files.
package ansible

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"gopkg.in/yaml.v3"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/ansible"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by FileRequired.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Extractor extracts container image references from Ansible playbook files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns an Ansible container image extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSize := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSize = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSize}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file is an Ansible playbook file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	filename := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	matched := false
	if filename == "playbook.yml" || filename == "playbook.yaml" ||
		filename == "site.yml" || filename == "site.yaml" ||
		filename == "deploy.yml" || filename == "deploy.yaml" ||
		filename == "main.yml" || filename == "main.yaml" ||
		filename == "setup.yml" || filename == "setup.yaml" ||
		filename == "install.yml" || filename == "install.yaml" {
		matched = true
	} else if strings.Contains(filename, "playbook") && (ext == ".yml" || ext == ".yaml") {
		matched = true
	}

	if !matched {
		return false
	}

	fi, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fi.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fi.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fi.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts container image references from an Ansible playbook file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := parse(input.Reader, input.Path)
	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, err)
		return inventory.Inventory{}, fmt.Errorf("ansible.parse(%q): %w", input.Path, err)
	}

	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, err error) {
	if e.Stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
}

func parse(r io.Reader, path string) ([]*extractor.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		log.Debugf("ansible: yaml unmarshal failed for %s: %v", path, err)
		return nil, nil
	}
	if len(root.Content) == 0 {
		return nil, nil
	}

	var pkgs []*extractor.Package
	seen := make(map[string]struct{})
	for _, doc := range root.Content {
		walkNode(doc, path, seen, &pkgs)
	}

	return pkgs, nil
}

func walkNode(node *yaml.Node, path string, seen map[string]struct{}, pkgs *[]*extractor.Package) {
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind == yaml.ScalarNode {
				if key.Value == "docker_container" || key.Value == "community.docker.docker_container" {
					valNode := node.Content[i+1]
					if valNode != nil && valNode.Kind == yaml.MappingNode {
						if imgNode := mappingValue(valNode, "image"); imgNode != nil && imgNode.Kind == yaml.ScalarNode {
							if pkg := packageFromImage(imgNode.Value, path); pkg != nil {
								if _, ok := seen[imgNode.Value]; !ok {
									seen[imgNode.Value] = struct{}{}
									*pkgs = append(*pkgs, pkg)
								}
							}
						}
					}
				}
			}
		}
	}
	for _, child := range node.Content {
		walkNode(child, path, seen, pkgs)
	}
}

func packageFromImage(image, path string) *extractor.Package {
	image = strings.TrimSpace(image)
	if image == "" {
		return nil
	}
	// Skip Jinja2 variable references
	if strings.Contains(image, "{{") || strings.Contains(image, "}}") {
		return nil
	}
	// Skip $ variables for safety
	if strings.Contains(image, "$") {
		return nil
	}

	name, version := parseName(image)
	return &extractor.Package{
		Name:     name,
		Version:  version,
		Location: extractor.LocationFromPath(path),
		PURLType: purl.TypeDocker,
	}
}

// parseName parses a container image name to extract the name and version/tag/digest.
// It handles both digest format (name@digest) and tag format (name:tag).
// If no version is specified, it returns "latest" as the default version.
func parseName(name string) (string, string) {
	if strings.Contains(name, "@") {
		parts := strings.SplitN(name, "@", 2)
		return parts[0], parts[1]
	}
	if lastColon := strings.LastIndex(name, ":"); lastColon != -1 {
		return name[:lastColon], name[lastColon+1:]
	}
	return name, "latest"
}

// mappingValue returns the value node associated with key in a YAML mapping
// node, or nil if the key isn't present.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

var _ filesystem.Extractor = Extractor{}
