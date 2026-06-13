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

// Package githubactionsimage extracts container image references from GitHub
// Actions workflow files (.github/workflows/*.yml and *.yaml).
package githubactionsimage

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
	Name = "containers/githubactionsimage"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by FileRequired.
	defaultMaxFileSizeBytes = 10 * units.MiB

	workflowsDir = ".github/workflows"
)

// Extractor extracts container image references from GitHub Actions workflow files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a GitHub Actions container image extractor.
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

// FileRequired returns true if the file is a GitHub Actions workflow file,
// i.e. is located directly under a .github/workflows/ directory and has a
// .yml or .yaml extension.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	ext := filepath.Ext(path)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	dir := filepath.ToSlash(filepath.Dir(path))
	if dir != workflowsDir && !strings.HasSuffix(dir, "/"+workflowsDir) {
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

// Extract extracts container image references from a GitHub Actions workflow file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := parse(input.Reader, input.Path)
	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, err)
		return inventory.Inventory{}, fmt.Errorf("githubactionsimage.parse(%q): %w", input.Path, err)
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
		log.Debugf("githubactionsimage: yaml unmarshal failed for %s: %v", path, err)
		return nil, nil
	}
	if len(root.Content) == 0 {
		return nil, nil
	}

	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, nil
	}

	jobs := mappingValue(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, nil
	}

	var pkgs []*extractor.Package
	seen := make(map[string]struct{})
	// MappingNode content alternates [key, value, key, value, ...].
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobNode := jobs.Content[i+1]
		if jobNode.Kind != yaml.MappingNode {
			continue
		}

		// jobs.<job_id>.container.image
		if container := mappingValue(jobNode, "container"); container != nil {
			var image string
			if container.Kind == yaml.ScalarNode {
				image = container.Value
			} else if container.Kind == yaml.MappingNode {
				if imgNode := mappingValue(container, "image"); imgNode != nil && imgNode.Kind == yaml.ScalarNode {
					image = imgNode.Value
				}
			}
			if pkg := packageFromImage(image, path); pkg != nil {
				key := pkg.Name + "@" + pkg.Version
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					pkgs = append(pkgs, pkg)
				}
			}
		}

		// jobs.<job_id>.services.<service_id>.image
		if services := mappingValue(jobNode, "services"); services != nil && services.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(services.Content); j += 2 {
				serviceNode := services.Content[j+1]
				if serviceNode.Kind != yaml.MappingNode {
					continue
				}
				if imgNode := mappingValue(serviceNode, "image"); imgNode != nil && imgNode.Kind == yaml.ScalarNode {
					if pkg := packageFromImage(imgNode.Value, path); pkg != nil {
						key := pkg.Name + "@" + pkg.Version
						if _, ok := seen[key]; !ok {
							seen[key] = struct{}{}
							pkgs = append(pkgs, pkg)
						}
					}
				}
			}
		}
	}

	return pkgs, nil
}

func packageFromImage(image, path string) *extractor.Package {
	image = strings.TrimSpace(image)
	if image == "" {
		return nil
	}
	// Skip unresolved variable references (e.g. $VAR, ${VAR})
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
