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

// Package argoworkflowimage extracts container image references from Argo Workflow YAML files.
package argoworkflowimage

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	Name = "containers/argoworkflowimage"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to process. If a file is encountered that is larger than this
	// limit, the file is skipped during processing.
	defaultMaxFileSizeBytes = 1 * units.MiB
)

// argoWorkflow represents an Argo Workflow resource with the fields needed for image extraction.
type argoWorkflow struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Spec       *argoWorkflowSpec `yaml:"spec,omitempty"`
}

// argoWorkflowSpec represents the spec section of an Argo Workflow resource.
// For CronWorkflow, the templates are nested under workflowSpec.
type argoWorkflowSpec struct {
	Templates    []argoTemplate    `yaml:"templates,omitempty"`
	WorkflowSpec *argoWorkflowSpec `yaml:"workflowSpec,omitempty"`
}

// argoTemplate represents a template in an Argo Workflow.
type argoTemplate struct {
	Container      *argoContainer  `yaml:"container,omitempty"`
	Script         *argoScript     `yaml:"script,omitempty"`
	InitContainers []argoContainer `yaml:"initContainers,omitempty"`
	Sidecars       []argoContainer `yaml:"sidecars,omitempty"`
}

// argoContainer represents a container specification in an Argo Workflow.
type argoContainer struct {
	Image string `yaml:"image"`
}

// argoScript represents a script specification in an Argo Workflow.
type argoScript struct {
	Image string `yaml:"image"`
}

// Extractor extracts container image references from Argo Workflow YAML files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns an Argo Workflow container image extractor.
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

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.ArgoWorkflowImageConfig {
		return c.GetArgoWorkflowImage()
	})
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSize = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSize}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file looks like a YAML file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// Extract extracts container image references from an Argo Workflow configuration file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info == nil {
		return inventory.Inventory{}, errors.New("input.Info is nil")
	}
	if input.Info.Size() > e.maxFileSizeBytes {
		log.Infof("Skipping too large file: %s", input.Path)
		return inventory.Inventory{}, nil
	}

	images, err := parseArgoWorkflowYAML(ctx, input.Reader)
	if err != nil {
		//nolint:nilerr
		return inventory.Inventory{}, nil
	}

	var pkgs []*extractor.Package
	for _, image := range images {
		name, version := parseName(image)
		pkgs = append(pkgs, &extractor.Package{
			Location: extractor.LocationFromPath(input.Path),
			Name:     name,
			Version:  version,
			PURLType: purl.TypeOCI,
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// parseName parses a container image name to extract the name and version/digest.
func parseName(name string) (string, string) {
	if strings.Contains(name, "@") {
		parts := strings.SplitN(name, "@", 2)
		return parts[0], parts[1]
	}
	if lastColonIndex := strings.LastIndex(name, ":"); lastColonIndex != -1 {
		return name[:lastColonIndex], name[lastColonIndex+1:]
	}
	return name, "latest"
}

// parseArgoWorkflowYAML extracts container images from Argo Workflow YAML documents.
func parseArgoWorkflowYAML(ctx context.Context, r io.Reader) ([]string, error) {
	decoder := yaml.NewDecoder(r)
	var images []string
	for {
		if err := ctx.Err(); err != nil {
			return images, fmt.Errorf("parseArgoWorkflowYAML halted due to context error: %w", err)
		}

		var doc argoWorkflow
		if err := decoder.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to parse Argo Workflow YAML: %w", err)
		}

		if doc.APIVersion == "" || doc.Kind == "" {
			return nil, errors.New("not an Argo Workflow file: missing 'apiVersion' or 'kind'")
		}

		if !strings.HasPrefix(doc.APIVersion, "argoproj.io/") {
			continue
		}

		if doc.Kind != "Workflow" && doc.Kind != "WorkflowTemplate" &&
			doc.Kind != "CronWorkflow" && doc.Kind != "ClusterWorkflowTemplate" {
			continue
		}

		extracted := extractImagesFromArgoWorkflow(&doc)
		images = append(images, extracted...)
	}

	return images, nil
}

// extractImagesFromArgoWorkflow extracts container images from an Argo Workflow resource.
// It handles both direct templates (Workflow, WorkflowTemplate, ClusterWorkflowTemplate)
// and nested templates in CronWorkflow (spec.workflowSpec.templates).
func extractImagesFromArgoWorkflow(doc *argoWorkflow) []string {
	if doc.Spec == nil {
		return nil
	}

	var images []string

	// Extract from direct templates (Workflow, WorkflowTemplate, ClusterWorkflowTemplate).
	images = append(images, extractImagesFromTemplates(doc.Spec.Templates)...)

	// Extract from CronWorkflow nested templates (spec.workflowSpec.templates).
	if doc.Spec.WorkflowSpec != nil {
		images = append(images, extractImagesFromTemplates(doc.Spec.WorkflowSpec.Templates)...)
	}

	return images
}

// extractImagesFromTemplates extracts container images from a list of Argo Workflow templates.
func extractImagesFromTemplates(templates []argoTemplate) []string {
	var images []string
	for _, tmpl := range templates {
		if tmpl.Container != nil && tmpl.Container.Image != "" {
			images = append(images, tmpl.Container.Image)
		}
		if tmpl.Script != nil && tmpl.Script.Image != "" {
			images = append(images, tmpl.Script.Image)
		}
		for _, ic := range tmpl.InitContainers {
			if ic.Image != "" {
				images = append(images, ic.Image)
			}
		}
		for _, sc := range tmpl.Sidecars {
			if sc.Image != "" {
				images = append(images, sc.Image)
			}
		}
	}
	return images
}
