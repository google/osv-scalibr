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

// Package azurepipelines extracts container image references from Azure Pipelines
// configuration files (azure-pipelines.yml / azure-pipelines.yaml).
package azurepipelines

import (
	"context"
	"errors"
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
	Name = "containers/azurepipelines"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by FileRequired.
	defaultMaxFileSizeBytes = 1 * units.MiB
)

// Extractor extracts container image references from Azure Pipelines configuration files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns an Azure Pipelines image extractor.
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

// FileRequired returns true if the specified file is an Azure Pipelines configuration file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	filename := strings.ToLower(filepath.Base(path))
	if filename != "azure-pipelines.yml" && filename != "azure-pipelines.yaml" {
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

// Extract extracts container image references from an Azure Pipelines configuration file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info == nil {
		return inventory.Inventory{}, errors.New("input.Info is nil")
	}
	if input.Info.Size() > e.maxFileSizeBytes {
		log.Infof("Skipping too large file: %s", input.Path)
		return inventory.Inventory{}, nil
	}

	pkgs, err := parse(input.Reader, input.Path)
	if err != nil {
		log.Debugf("azurepipelines: parse failed for %s: %v", input.Path, err)
		return inventory.Inventory{}, nil
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
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}

	var pkgs []*extractor.Package
	seen := make(map[string]struct{})

	// The root of a YAML document is a DocumentNode with one child (the actual content).
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = *root.Content[0]
	}

	if root.Kind != yaml.MappingNode {
		return pkgs, nil
	}

	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i].Value
		val := root.Content[i+1]

		switch key {
		case "resources":
			extractResources(val, path, seen, &pkgs)
		case "jobs":
			extractJobs(val, path, seen, &pkgs)
		}
	}

	return pkgs, nil
}

func extractResources(node *yaml.Node, path string, seen map[string]struct{}, pkgs *[]*extractor.Package) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value != "containers" {
			continue
		}
		containers := node.Content[i+1]
		if containers.Kind != yaml.SequenceNode {
			return
		}
		for _, container := range containers.Content {
			if container.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j < len(container.Content); j += 2 {
				if container.Content[j].Value == "image" {
					image := strings.TrimSpace(container.Content[j+1].Value)
					addImage(image, path, seen, pkgs)
				}
			}
		}
	}
}

func extractJobs(node *yaml.Node, path string, seen map[string]struct{}, pkgs *[]*extractor.Package) {
	if node.Kind != yaml.SequenceNode {
		return
	}
	for _, job := range node.Content {
		if job.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(job.Content); i += 2 {
			key := job.Content[i].Value
			val := job.Content[i+1]

			switch key {
			case "container":
				extractContainerImage(val, path, seen, pkgs)
			case "steps":
				extractSteps(val, path, seen, pkgs)
			}
		}
	}
}

func extractSteps(node *yaml.Node, path string, seen map[string]struct{}, pkgs *[]*extractor.Package) {
	if node.Kind != yaml.SequenceNode {
		return
	}
	for _, step := range node.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(step.Content); i += 2 {
			if step.Content[i].Value == "container" {
				extractContainerImage(step.Content[i+1], path, seen, pkgs)
			}
		}
	}
}

func extractContainerImage(node *yaml.Node, path string, seen map[string]struct{}, pkgs *[]*extractor.Package) {
	switch node.Kind {
	case yaml.ScalarNode:
		image := strings.TrimSpace(node.Value)
		addImage(image, path, seen, pkgs)
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value == "image" {
				image := strings.TrimSpace(node.Content[i+1].Value)
				addImage(image, path, seen, pkgs)
			}
		}
	}
}

func addImage(image, path string, seen map[string]struct{}, pkgs *[]*extractor.Package) {
	if image == "" {
		return
	}
	if strings.Contains(image, "$(") {
		return
	}
	if _, ok := seen[image]; ok {
		return
	}
	seen[image] = struct{}{}

	name, version := parseName(image)
	*pkgs = append(*pkgs, &extractor.Package{
		Location: extractor.LocationFromPath(path),
		Name:     name,
		Version:  version,
		PURLType: purl.TypeDocker,
	})
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

var _ filesystem.Extractor = Extractor{}
