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
	"os"
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
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by `FileRequired`.
	DefaultMaxFileSizeBytes = 1 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
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

// FileRequired returns true if the specified file looks like a Kubernetes YAML.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	// Only consider YAML/YML files.
	path := api.Path()
	fileName := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(fileName))
	if ext != ".yaml" && ext != ".yml" {
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)

	var hasK8sKeys func(v any) bool
	hasK8sKeys = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			_, hasAPIVersion := x["apiVersion"]
			_, hasKind := x["kind"]
			if hasAPIVersion && hasKind {
				return true
			}
			for _, vv := range x {
				if hasK8sKeys(vv) {
					return true
				}
			}
		case []any:
			for _, it := range x {
				if hasK8sKeys(it) {
					return true
				}
			}
		}
		return false
	}

	for {
		var doc any
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false
		}
		if hasK8sKeys(doc) {
			return true
		}
	}
	return false
}

// Extract extracts container image references from a K8s configuration file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info == nil {
		return inventory.Inventory{}, errors.New("input.Info is nil")
	}
	if input.Info.Size() > e.maxFileSizeBytes {
		// Skipping a too large file.
		log.Infof("Skipping too large file: %s", input.Path)
		return inventory.Inventory{}, nil
	}

	images, err := parseK8sYAML(input.Reader)
	if err != nil {
		log.Warnf("Parsing error: %v", err)
		return inventory.Inventory{}, err
	}

	var pkgs []*extractor.Package
	for _, image := range images {
		name, version := parseName(image)
		pkgs = append(pkgs, &extractor.Package{
			Locations: []string{input.Path},
			Name:      name,
			Version:   version,
			PURLType:  purl.TypeDocker,
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

func parseName(name string) (string, string) {
	// https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy
	if strings.Contains(name, "@") {
		parts := strings.SplitN(name, "@", 2)
		return parts[0], parts[1]
	}

	if strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		return parts[0], parts[1]
	}

	return name, "latest"
}

// parseK8sYAML extracts container images from Kubernetes YAML
func parseK8sYAML(r io.Reader) ([]string, error) {
	decoder := yaml.NewDecoder(r)
	var images []string

	for {
		// Parse each YAML document in the file
		var doc map[string]any
		if err := decoder.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to parse Kubernetes YAML: %w", err)
		}

		// Extract images from the document
		extractedImages := extractImagesFromK8sDoc(doc)
		images = append(images, extractedImages...)
	}

	return images, nil
}

// extractImagesFromK8sDoc recursively extracts container images from a K8s resource
func extractImagesFromK8sDoc(doc map[string]any) []string {
	var images []string

	if spec, ok := doc["spec"].(map[string]any); ok {
		// Check for direct containers at spec.containers
		// Handle containers
		images = append(images, getImagesFromContainers(spec, "containers")...)
		// Handle initContainers
		images = append(images, getImagesFromContainers(spec, "initContainers")...)

		// Check for template-based resources (Deployments, StatefulSets, etc.)
		if template, ok := spec["template"].(map[string]any); ok {
			if templateSpec, ok := template["spec"].(map[string]any); ok {
				images = append(images, getImagesFromContainers(templateSpec, "containers")...)
				images = append(images, getImagesFromContainers(templateSpec, "initContainers")...)
			}
		}

		// Handle CronJob/Job templates
		if jobTemplate, ok := spec["jobTemplate"].(map[string]any); ok {
			if jobSpec, ok := jobTemplate["spec"].(map[string]any); ok {
				if template, ok := jobSpec["template"].(map[string]any); ok {
					if templateSpec, ok := template["spec"].(map[string]any); ok {
						images = append(images, getImagesFromContainers(templateSpec, "containers")...)
						images = append(images, getImagesFromContainers(templateSpec, "initContainers")...)
					}
				}
			}
		}
	}

	return images
}

// getImagesFromContainers extracts image references from a container list
func getImagesFromContainers(spec map[string]any, containerType string) []string {
	var images []string
	if containers, ok := spec[containerType].([]any); ok {
		for _, c := range containers {
			if container, ok := c.(map[string]any); ok {
				if image, ok := container["image"].(string); ok && image != "" {
					images = append(images, image)
				}
			}
		}
	}
	return images
}
