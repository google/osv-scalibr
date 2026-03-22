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

// Package argocdimage extracts OCI image references from Argo CD Application YAML files.
package argocdimage

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
	Name = "containers/argocdimage"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to process. If a file is encountered that is larger than this
	// limit, the file is skipped during processing.
	defaultMaxFileSizeBytes = 1 * units.MiB
)

// argoCDApplication represents an Argo CD Application resource.
type argoCDApplication struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Spec       *argoCDAppSpec `yaml:"spec,omitempty"`
}

// argoCDAppSpec represents the spec section of an Argo CD Application.
type argoCDAppSpec struct {
	Source  *argoCDSource  `yaml:"source,omitempty"`
	Sources []argoCDSource `yaml:"sources,omitempty"`
}

// argoCDSource represents a source in an Argo CD Application.
type argoCDSource struct {
	RepoURL        string `yaml:"repoURL"`
	TargetRevision string `yaml:"targetRevision"`
	Chart          string `yaml:"chart,omitempty"`
	Path           string `yaml:"path,omitempty"`
}

// Extractor extracts OCI image references from Argo CD Application YAML files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns an Argo CD image extractor.
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

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.ArgoCDImageConfig {
		return c.GetArgoCdImage()
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

// Extract extracts OCI image references from an Argo CD Application configuration file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info == nil {
		return inventory.Inventory{}, errors.New("input.Info is nil")
	}
	if input.Info.Size() > e.maxFileSizeBytes {
		log.Infof("Skipping too large file: %s", input.Path)
		return inventory.Inventory{}, nil
	}

	sources, err := parseArgoCDYAML(ctx, input.Reader)
	if err != nil {
		//nolint:nilerr
		return inventory.Inventory{}, nil
	}

	var pkgs []*extractor.Package
	for _, src := range sources {
		if src.RepoURL == "" || src.TargetRevision == "" {
			continue
		}

		name := buildName(src)

		pkgs = append(pkgs, &extractor.Package{
			Location: extractor.LocationFromPath(input.Path),
			Name:     name,
			Version:  src.TargetRevision,
			PURLType: purl.TypeOCI,
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// buildName constructs the package name from the source.
// If a chart is specified, the name is repoURL/chart (e.g. "registry-1.docker.io/bitnamicharts/nginx").
// If a path is specified, the name is repoURL/path (e.g. "registry-1.docker.io/bitnamicharts/nginx").
// Otherwise, the name is just the repoURL.
func buildName(src argoCDSource) string {
	if src.Chart != "" {
		return strings.TrimRight(src.RepoURL, "/") + "/" + src.Chart
	}
	if src.Path != "" {
		return strings.TrimRight(src.RepoURL, "/") + "/" + src.Path
	}
	return src.RepoURL
}

// parseArgoCDYAML extracts source references from Argo CD Application YAML documents.
func parseArgoCDYAML(ctx context.Context, r io.Reader) ([]argoCDSource, error) {
	decoder := yaml.NewDecoder(r)
	var sources []argoCDSource
	for {
		if err := ctx.Err(); err != nil {
			return sources, fmt.Errorf("parseArgoCDYAML halted due to context error: %w", err)
		}

		var doc argoCDApplication
		if err := decoder.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to parse Argo CD YAML: %w", err)
		}

		if doc.APIVersion == "" || doc.Kind == "" {
			return nil, errors.New("not an Argo CD file: missing 'apiVersion' or 'kind'")
		}

		if !strings.HasPrefix(doc.APIVersion, "argoproj.io/") {
			continue
		}

		if doc.Kind != "Application" && doc.Kind != "ApplicationSet" {
			continue
		}

		extracted := extractSourcesFromArgoCDApp(&doc)
		sources = append(sources, extracted...)
	}

	return sources, nil
}

// extractSourcesFromArgoCDApp extracts source references from an Argo CD Application resource.
func extractSourcesFromArgoCDApp(doc *argoCDApplication) []argoCDSource {
	var sources []argoCDSource

	if doc.Spec == nil {
		return sources
	}

	if doc.Spec.Source != nil {
		sources = append(sources, *doc.Spec.Source)
	}

	sources = append(sources, doc.Spec.Sources...)

	return sources
}
