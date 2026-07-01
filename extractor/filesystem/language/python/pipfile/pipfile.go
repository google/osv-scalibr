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

// Package pipfile extracts inventory from Pipfile Python manifests.
package pipfile

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pipfile"
)

// pipfile represents the parsed Pipfile structure.
// We only care about the [packages] and [dev-packages] tables.
type pipfile struct {
	Packages    map[string]any `toml:"packages"`
	DevPackages map[string]any `toml:"dev-packages"`
}

// Extractor extracts python packages from Pipfile files.
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

// FileRequired returns true if the specified file is a Pipfile.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Pipfile"
}

// Extract extracts dependencies from a Pipfile.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	var doc pipfile
	if err := toml.Unmarshal(content, &doc); err != nil {
		return inventory.Inventory{}, fmt.Errorf("toml.Unmarshal(%s): %w", input.Path, err)
	}

	packages := make([]*extractor.Package, 0)

	// Extract packages from [packages].
	for name, details := range doc.Packages {
		pkg := parseDependency(name, details, "")
		if pkg != nil {
			pkg.Location = extractor.LocationFromPath(input.Path)
			pkg.PURLType = purl.TypePyPi
			packages = append(packages, pkg)
		}
	}

	// Extract packages from [dev-packages].
	for name, details := range doc.DevPackages {
		pkg := parseDependency(name, details, "dev")
		if pkg != nil {
			pkg.Location = extractor.LocationFromPath(input.Path)
			pkg.PURLType = purl.TypePyPi
			packages = append(packages, pkg)
		}
	}

	return inventory.Inventory{Packages: packages}, nil
}

// parseDependency parses a single dependency entry from a Pipfile.
// Returns nil if the dependency should be skipped (e.g., git, path, editable).
func parseDependency(name string, details any, depGroup string) *extractor.Package {
	version, ok := extractVersionConstraint(name, details)
	if !ok {
		return nil
	}

	// "*" means any version — treat as empty version string.
	if version == "*" {
		version = ""
	} else {
		version = normalizeVersionConstraint(version)
	}

	pkg := &extractor.Package{
		Name:    name,
		Version: version,
	}

	if depGroup != "" {
		pkg.Metadata = &osv.DepGroupMetadata{
			DepGroupVals: []string{depGroup},
		}
	}

	return pkg
}

// extractVersionConstraint parses a single dependency entry from a Pipfile.
// It returns the version constraint string and a boolean indicating if parsing was successful.
// It skips over non-version dependencies like git, path, file, or editable references.
func extractVersionConstraint(name string, details any) (string, bool) {
	switch v := details.(type) {
	case string:
		return v, true
	case map[string]any:
		if vs, ok := v["version"].(string); ok {
			return vs, true
		} else if _, ok := v["git"]; ok {
			log.Infof("Skipping git dependency in Pipfile for package %q", name)
			return "", false
		} else if _, ok := v["path"]; ok {
			log.Infof("Skipping path dependency in Pipfile for package %q", name)
			return "", false
		} else if _, ok := v["file"]; ok {
			log.Infof("Skipping file dependency in Pipfile for package %q", name)
			return "", false
		} else if _, ok := v["editable"]; ok {
			log.Infof("Skipping editable dependency in Pipfile for package %q", name)
			return "", false
		}
	default:
		log.Warnf("Unsupported dependency format in Pipfile for package %q", name)
		return "", false
	}

	return "", false
}

func normalizeVersionConstraint(version string) string {
	version = strings.TrimSpace(version)
	for _, sep := range []string{"===", "==", ">=", "<=", "~="} {
		if v, ok := strings.CutPrefix(version, sep); ok {
			return strings.TrimSpace(v)
		}
	}
	return version
}
