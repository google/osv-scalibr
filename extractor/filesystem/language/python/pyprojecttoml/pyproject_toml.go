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

// Package pyprojecttoml extracts inventory from pyproject.toml Python manifests.
// Supports PEP 621 [project] dependencies and optional-dependencies.
package pyprojecttoml

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pyprojecttoml"
)

// pyprojectTOML represents the parsed pyproject.toml structure.
// It models the [project] table used by PEP 621 dependencies.
type pyprojectTOML struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
}

var (
	// reStripExtras removes [extras] from package names.
	reStripExtras = regexp.MustCompile(`\[.*\]`)
	// reStripMarkers removes ; environment markers from requirement strings.
	reStripMarkers = regexp.MustCompile(`;.*`)
	// reStripWhitespace removes all whitespace.
	reStripWhitespace = regexp.MustCompile(`\s+`)
	// reVersionConstraint matches version constraints like >=1.0, ==2.0, etc.
	reVersionConstraint = regexp.MustCompile(`^([a-zA-Z0-9_.-]+)(===|==|~=|>=|<=|>|<|!=)(.*)$`)
)

// Extractor extracts python packages from pyproject.toml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a pyproject.toml file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pyproject.toml"
}

// Extract extracts dependencies from a pyproject.toml file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	var doc pyprojectTOML
	if err := toml.Unmarshal(content, &doc); err != nil {
		return inventory.Inventory{}, fmt.Errorf("toml.Unmarshal(%s): %w", input.Path, err)
	}

	packages := make([]*extractor.Package, 0)

	// Extract main dependencies from [project.dependencies].
	for _, req := range doc.Project.Dependencies {
		pkg := parseRequirement(req, "")
		if pkg != nil {
			pkg.Location = extractor.LocationFromPath(input.Path)
			pkg.PURLType = purl.TypePyPi
			packages = append(packages, pkg)
		}
	}

	// Extract optional dependencies from [project.optional-dependencies].
	for group, reqs := range doc.Project.OptionalDependencies {
		for _, req := range reqs {
			pkg := parseRequirement(req, group)
			if pkg != nil {
				pkg.Location = extractor.LocationFromPath(input.Path)
				pkg.PURLType = purl.TypePyPi
				packages = append(packages, pkg)
			}
		}
	}

	return inventory.Inventory{Packages: packages}, nil
}

// parseRequirement parses a single PEP 508 requirement string and returns a Package.
// Returns nil if the requirement should be skipped (e.g., URL dependency).
func parseRequirement(req string, depGroup string) *extractor.Package {
	req = strings.TrimSpace(req)
	if req == "" {
		return nil
	}

	// Skip URL dependencies (e.g., "package @ https://...").
	if strings.Contains(req, "@") {
		return nil
	}

	// Strip extras (e.g., "pytest[testing]" -> "pytest").
	req = reStripExtras.ReplaceAllString(req, "")

	// Strip environment markers (e.g., "requests; python_version >= \"3.8\"").
	req = reStripMarkers.ReplaceAllString(req, "")

	req = strings.TrimSpace(req)

	name, version := getLowestVersion(req)
	if name == "" {
		return nil
	}

	pkg := &extractor.Package{
		Name:    name,
		Version: version,
	}

	// Set dependency group metadata.
	if depGroup != "" {
		groupValue := depGroup
		if groupValue == "dev" || groupValue == "test" {
			groupValue = "dev"
		}
		pkg.Metadata = &osv.DepGroupMetadata{DepGroupVals: []string{groupValue}}
	}

	return pkg
}

// getLowestVersion extracts the package name and version from a PEP 508 requirement string.
// It returns the name and the lowest version constraint found.
// If no version is found, returns the name with an empty version string.
func getLowestVersion(s string) (string, string) {
	// Normalize: strip all whitespace.
	s = reStripWhitespace.ReplaceAllString(s, "")

	match := reVersionConstraint.FindStringSubmatch(s)
	if match == nil {
		// No version constraint - just a package name.
		return s, ""
	}

	name := strings.ToLower(match[1])
	operator := match[2]
	version := match[3]

	// Strip any trailing constraints after comma.
	if idx := strings.Index(version, ","); idx != -1 {
		version = version[:idx]
	}

	// For unsupported operators, return name with empty version.
	if operator == "!=" || operator == "<" || operator == ">" {
		return name, ""
	}

	// For ~= compatible release, return as-is.
	if operator == "~=" {
		return name, operator + version
	}

	// For ===, ==, >=, <=, return operator + version.
	return name, operator + version
}
