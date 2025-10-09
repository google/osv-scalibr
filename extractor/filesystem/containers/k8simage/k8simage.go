// Copyright 2025 Google LLC
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

// Package k8simage extracts container image references from Kubernetes YAML files.
package k8simage

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
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/k8simage"

	// DefaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to process. If a file is encountered that is larger than this
	// limit, the file is skipped during processing.
	DefaultMaxFileSizeBytes = 1 * units.MiB
)

// k8sResource represents a Kubernetes resource with the fields needed for image extraction.
type k8sResource struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Spec       *k8sSpec `yaml:"spec,omitempty"`
}

// k8sSpec represents the spec section of a Kubernetes resource.
type k8sSpec struct {
	Containers     []container  `yaml:"containers,omitempty"`
	InitContainers []container  `yaml:"initContainers,omitempty"`
	Template       *podTemplate `yaml:"template,omitempty"`
	JobTemplate    *jobTemplate `yaml:"jobTemplate,omitempty"`
}

// jobTemplate represents a job template in CronJob resources.
type jobTemplate struct {
	Spec *jobSpec `yaml:"spec,omitempty"`
}

// jobSpec represents the spec of a Job.
type jobSpec struct {
	Template *podTemplate `yaml:"template,omitempty"`
}

// podTemplate represents a pod template in Kubernetes resources.
type podTemplate struct {
	Spec *podSpec `yaml:"spec,omitempty"`
}

// podSpec represents a pod specification.
type podSpec struct {
	Containers     []container `yaml:"containers,omitempty"`
	InitContainers []container `yaml:"initContainers,omitempty"`
}

// container represents a container specification in Kubernetes.
type container struct {
	Image string `yaml:"image"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` receives a larger file, it will return false.
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: DefaultMaxFileSizeBytes,
	}
}

// Extractor extracts container image references from Kubernetes YAML files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Kubernetes container image extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file looks like a Kubernetes YAML file.
// It determines if the specified file is a Kubernetes YAML file that should be processed
// by checking the file extension (.yaml or .yml).
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	// Only consider YAML/YML files
	path := api.Path()
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// Extract extracts container image references from a K8s configuration file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info == nil {
		return inventory.Inventory{}, errors.New("input.Info is nil")
	}
	if input.Info.Size() > e.maxFileSizeBytes {
		// Skip file that exceeds size limit.
		log.Infof("Skipping too large file: %s", input.Path)
		return inventory.Inventory{}, nil
	}

	images, err := parseK8sYAML(ctx, input.Reader)
	if err != nil {
		// Not a K8s YAML file.
		//nolint:nilerr
		return inventory.Inventory{}, nil
	}

	var pkgs []*extractor.Package
	for _, image := range images {
		name, version := parseName(image)
		pkgs = append(pkgs, &extractor.Package{
			Locations: []string{input.Path},
			Name:      name,
			Version:   version,
			PURLType:  purl.TypeK8s,
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// parseName parses a container image name to extract the name and version/digest.
// It handles both digest (@sha256:...) and tag (:tag) formats.
// See: https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy
func parseName(name string) (string, string) {
	// Handle digest format (tag@HashType:HashValue)
	if strings.Contains(name, "@") {
		parts := strings.SplitN(name, "@", 2)
		return parts[0], parts[1]
	}
	// Handle tag format (registry:port/namespace/image:tag)
	// Use LastIndex to find the rightmost colon which separates the tag
	if lastColonIndex := strings.LastIndex(name, ":"); lastColonIndex != -1 {
		return name[:lastColonIndex], name[lastColonIndex+1:]
	}

	return name, "latest"
}

// parseK8sYAML extracts container images from Kubernetes YAML documents.
// It supports multi-document YAML files and validates that each document
// contains the required apiVersion and kind fields.
func parseK8sYAML(ctx context.Context, r io.Reader) ([]string, error) {
	decoder := yaml.NewDecoder(r)
	var images []string
	for {
		// Check for context cancellation during parsing
		if err := ctx.Err(); err != nil {
			return images, fmt.Errorf("parseK8sYAML halted due to context error: %w", err)
		}

		// Parse each YAML document in the file
		var doc k8sResource
		if err := decoder.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to parse Kubernetes YAML: %w", err)
		}
		// Check if the document is a Kubernetes resource by checking for "apiVersion" and "kind" fields
		if doc.APIVersion == "" || doc.Kind == "" {
			return nil, errors.New("not a Kubernetes configuration file: missing 'apiVersion' or 'kind'")
		}
		// Extract images from the document
		extractedImages := extractImagesFromK8sResource(&doc)
		images = append(images, extractedImages...)
	}

	return images, nil
}

// extractImagesFromK8sResource extracts container images from a Kubernetes resource.
// It handles various resource types including Pods, Deployments, StatefulSets, Jobs, and CronJobs.
func extractImagesFromK8sResource(doc *k8sResource) []string {
	var images []string

	if doc.Spec == nil {
		return images
	}

	// Check for direct containers at spec.containers
	images = append(images, getImagesFromContainerList(doc.Spec.Containers)...)
	// Handle initContainers
	images = append(images, getImagesFromContainerList(doc.Spec.InitContainers)...)

	// Check for template-based resources (Deployments, StatefulSets, etc.)
	if doc.Spec.Template != nil && doc.Spec.Template.Spec != nil {
		images = append(images, getImagesFromContainerList(doc.Spec.Template.Spec.Containers)...)
		images = append(images, getImagesFromContainerList(doc.Spec.Template.Spec.InitContainers)...)
	}

	// Handle CronJob/Job templates
	if doc.Spec.JobTemplate != nil && doc.Spec.JobTemplate.Spec != nil &&
		doc.Spec.JobTemplate.Spec.Template != nil && doc.Spec.JobTemplate.Spec.Template.Spec != nil {
		images = append(images, getImagesFromContainerList(doc.Spec.JobTemplate.Spec.Template.Spec.Containers)...)
		images = append(images, getImagesFromContainerList(doc.Spec.JobTemplate.Spec.Template.Spec.InitContainers)...)
	}

	return images
}

// getImagesFromContainerList extracts image references from a list of containers,
// filtering out any containers with empty image fields.
func getImagesFromContainerList(containers []container) []string {
	var images []string
	for _, container := range containers {
		if container.Image != "" {
			images = append(images, container.Image)
		}
	}
	return images
}
