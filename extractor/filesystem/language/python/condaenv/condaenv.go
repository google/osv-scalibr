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

// Package condaenv extracts packages declared in Conda environment.yml files.
//
// Unlike the condameta extractor which reads installed package metadata from
// conda-meta/*.json files, this extractor parses the declarative
// environment.yml format. These files are the standard way Conda users
// share reproducible environments (e.g. in GitHub repos, Docker images,
// scientific papers, and CI/CD pipelines).
//
// environment.yml is also used by:
//   - conda env create -f environment.yml
//   - Google Colab and JupyterHub environment specs
//   - Bioinformatics pipeline tools (Snakemake, Nextflow)
//   - ML research repositories (PyTorch, JAX, etc.)
//
// File format example:
//
//	name: myenv
//	channels:
//	  - conda-forge
//	  - defaults
//	dependencies:
//	  - python=3.11
//	  - numpy=1.26.0
//	  - scipy>=1.11
//	  - pip:
//	    - requests==2.31.0
package condaenv

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"gopkg.in/yaml.v3"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/condaenv"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 1 * units.MiB
)

// environmentYML is the top-level structure of a Conda environment.yml file.
type environmentYML struct {
	Name         string   `yaml:"name"`
	Channels     []string `yaml:"channels"`
	Dependencies []any    `yaml:"dependencies"`
}

// Extractor extracts Conda packages from environment.yml files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a new Conda environment.yml extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is a Conda environment.yml or environment.yaml.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())
	if base != "environment.yml" && base != "environment.yaml" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(api.Path(), fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(api.Path(), fileinfo.Size(), stats.FileRequiredResultOK)
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

// Extract extracts conda packages from an environment.yml file.
//
// Conda dependency strings can be:
//   - "numpy"              (just a name, any version)
//   - "numpy=1.26.0"       (exact version, pinned with single =)
//   - "numpy>=1.26,<2.0"   (version range)
//   - "python=3.11.*"      (wildcard)
//
// Pip dependencies (under the "pip:" key) are skipped; they are handled
// by Python/pip extractors.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var env environmentYML
	if err := yaml.NewDecoder(input.Reader).Decode(&env); err != nil {
		return inventory.Inventory{}, fmt.Errorf("condaenv: yaml.Decode(%s): %w", input.Path, err)
	}

	var pkgs []*extractor.Package
	for _, dep := range env.Dependencies {
		switch v := dep.(type) {
		case string:
			// A plain conda dependency string like "numpy=1.26.0"
			if pkg := parseCondaDep(v, input.Path); pkg != nil {
				pkgs = append(pkgs, pkg)
			}
		case map[string]any:
			// A nested mapping, typically {"pip": [...]}
			// We intentionally skip pip dependencies — they belong to PyPI.
			// Other nested forms (e.g. conda-lock specific) are also skipped.
		}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// parseCondaDep parses a conda dependency string into an extractor.Package.
//
// Conda dependency format: name[=version[=build_string]]
// The conda pinning operators are: = (exact), >= (min), <= (max), != (excluded)
//
// Examples:
//
//	"numpy"           → name=numpy, version=""
//	"numpy=1.26.0"    → name=numpy, version=1.26.0
//	"numpy>=1.26"     → name=numpy, version=>=1.26 (kept as-is for matching)
//	"python=3.11.*"   → name=python, version=3.11.*
func parseCondaDep(dep string, path string) *extractor.Package {
	dep = strings.TrimSpace(dep)
	if dep == "" {
		return nil
	}

	// Split on the first version operator character.
	// Operators: =, >=, <=, !=, ~=
	// We find the first non-name character.
	name := dep
	version := ""

	for _, op := range []string{"!=", "~=", ">=", "<=", "==", "="} {
		if idx := strings.Index(dep, op); idx > 0 {
			candidate := strings.TrimSpace(dep[:idx])
			if isValidCondaName(candidate) {
				name = candidate
				version = strings.TrimSpace(dep[idx+len(op):])
				break
			}
		}
	}

	// Strip the build string if present (second = in "numpy=1.26.0=py311_0")
	if idx := strings.Index(version, "="); idx >= 0 {
		version = version[:idx]
	}

	// Skip meta-packages and wildcards-only versions.
	if name == "" {
		return nil
	}

	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeConda,
		Location: extractor.LocationFromPath(path),
	}
}

// isValidCondaName returns true if s looks like a valid conda package name.
// Conda names consist of letters, digits, hyphens, underscores, and dots.
func isValidCondaName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
