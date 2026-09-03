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

// Package gradleversioncatalog extracts Gradle Version Catalog files
// (libs.versions.toml) used by Gradle 7.0+ to centralize Maven-coordinate
// dependency declarations across multi-module builds.
package gradleversioncatalog

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/gradleversioncatalog"
)

// catalogFile is the top-level shape of a libs.versions.toml document.
// The [bundles] and [plugins] tables are intentionally not parsed:
// bundles only group already-declared libraries, and Gradle plugins
// resolve to a different PURL space than Maven artifacts.
type catalogFile struct {
	Versions  map[string]string `toml:"versions"`
	Libraries map[string]any    `toml:"libraries"`
}

// Extractor extracts Maven packages from Gradle Version Catalog files.
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

// FileRequired returns true if the specified file matches the Gradle
// Version Catalog naming convention. The default catalog filename is
// libs.versions.toml; additional catalogs may be declared under any
// *.versions.toml name inside a gradle/ directory.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	base := filepath.Base(path)
	if base == "libs.versions.toml" {
		return true
	}
	if strings.HasSuffix(base, ".versions.toml") {
		dir := filepath.Base(filepath.Dir(path))
		return dir == "gradle"
	}
	return false
}

// Extract parses a libs.versions.toml file and returns its declared
// libraries as Maven packages.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var cf catalogFile
	if _, err := toml.NewDecoder(input.Reader).Decode(&cf); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to parse %q: %w", input.Path, err)
	}

	var packages []*extractor.Package
	for _, raw := range cf.Libraries {
		group, artifact, version, ok := resolveLibrary(raw, cf.Versions)
		if !ok {
			continue
		}
		packages = append(packages, &extractor.Package{
			Name:     fmt.Sprintf("%s:%s", group, artifact),
			Version:  version,
			PURLType: purl.TypeMaven,
			Metadata: &javalockfile.Metadata{
				ArtifactID: artifact,
				GroupID:    group,
			},
			Location: extractor.LocationFromPath(input.Path),
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

// resolveLibrary normalizes the four shapes a [libraries] entry can take
// into (group, artifact, version). It returns ok=false when the entry is
// missing required coordinates or uses unresolvable version refs.
//
// Shapes accepted (per Gradle Version Catalog spec):
//  1. String shorthand:           "group:artifact:version"
//  2. Inline table with module:   { module = "g:a", version = "1.0" }
//  3. Inline table with module
//     and version.ref shorthand:  { module = "g:a", version.ref = "alias" }
//  4. Inline table with explicit
//     group/name fields:          { group = "g", name = "a", version = "1.0" }
//
// The version field itself may be: a string, a {ref = "alias"} table, or a
// rich version table containing strictly/require/prefer. A missing version
// resolves to empty (Gradle allows version-less entries; downstream tools
// treat them as unpinned).
func resolveLibrary(raw any, versions map[string]string) (group, artifact, version string, ok bool) {
	switch v := raw.(type) {
	case string:
		parts := strings.SplitN(v, ":", 3)
		if len(parts) < 2 {
			return "", "", "", false
		}
		if len(parts) == 2 {
			return parts[0], parts[1], "", true
		}
		return parts[0], parts[1], parts[2], true

	case map[string]any:
		if module, hasModule := v["module"].(string); hasModule {
			parts := strings.SplitN(module, ":", 2)
			if len(parts) != 2 {
				return "", "", "", false
			}
			group, artifact = parts[0], parts[1]
		} else if g, hasGroup := v["group"].(string); hasGroup {
			n, hasName := v["name"].(string)
			if !hasName {
				return "", "", "", false
			}
			group, artifact = g, n
		} else {
			return "", "", "", false
		}
		version = resolveVersion(v["version"], versions)
		return group, artifact, version, true
	}
	return "", "", "", false
}

// resolveVersion turns the polymorphic `version` field into a concrete
// string. Returns "" when the value is missing or references an undefined
// alias — downstream callers may still emit the package as unpinned.
//
// Resolution order, mirroring Gradle's runtime behavior:
//   - rich {strictly} wins over {require} wins over {prefer}
//   - {ref} indirects into the [versions] table
func resolveVersion(raw any, versions map[string]string) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case string:
		return v
	case map[string]any:
		if ref, ok := v["ref"].(string); ok {
			return versions[ref]
		}
		if s, ok := v["strictly"].(string); ok {
			return s
		}
		if s, ok := v["require"].(string); ok {
			return s
		}
		if s, ok := v["prefer"].(string); ok {
			return s
		}
	}
	return ""
}

var _ filesystem.Extractor = Extractor{}
