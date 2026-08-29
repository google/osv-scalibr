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

// Package pipfile extracts Python dependencies from Pipfile (Pipenv) source
// manifests. Only the top-level [packages] and [dev-packages] TOML tables are
// parsed. Entries may be plain version-specifier strings ("==2.0.1", "*",
// ">=1.20.0,<2.0.0") or inline tables with a "version" field
// ({ version = ">=3.2" }). Only exact pins (==X.Y.Z) yield a concrete version
// in the emitted PURL; all other constraints produce a name-only PURL because
// the source manifest does not identify an installed version. VCS, editable,
// and local-path entries (tables without a "version" field) are skipped.
// Pipfile.lock is handled by the separate python/pipfilelock extractor.
package pipfile

import (
	"bufio"
	"bytes"
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

	// Keyword that SCALIBR uses for packages in the dev group.
	groupDev = "dev"

	sectionPackages    = "packages"
	sectionDevPackages = "dev-packages"
)

// pipfile represents the relevant top-level tables of a Pipfile.
type pipfile struct {
	Packages    map[string]any `toml:"packages"`
	DevPackages map[string]any `toml:"dev-packages"`
}

// Extractor extracts Python packages from Pipfile source manifests.
type Extractor struct{}

var _ filesystem.Extractor = Extractor{}

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

// FileRequired returns true if the file basename is exactly "Pipfile".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Pipfile"
}

// Extract extracts packages from a Pipfile passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	if len(strings.TrimSpace(string(content))) == 0 {
		return inventory.Inventory{}, nil
	}

	var pf pipfile
	if err := toml.Unmarshal(content, &pf); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	var packages []*extractor.Package
	packages = append(packages, extractSection(input.Path, content, pf.Packages, sectionPackages, "")...)
	packages = append(packages, extractSection(input.Path, content, pf.DevPackages, sectionDevPackages, groupDev)...)

	return inventory.Inventory{Packages: packages}, nil
}

// extractSection converts a single [packages] or [dev-packages] table into
// extractor.Package entries. Entries without a usable version spec (e.g.
// VCS/editable/path-only tables) are skipped.
func extractSection(path string, content []byte, pkgs map[string]any, section, group string) []*extractor.Package {
	var packages []*extractor.Package
	for name, val := range pkgs {
		spec, ok := versionSpec(val)
		if !ok {
			continue
		}

		version := extractVersion(spec)
		line := findPackageLine(content, section, name)

		var loc extractor.PackageLocation
		if line > 0 {
			loc = extractor.LocationFromPathAndLine(path, line)
		} else {
			log.Debugf("Failed to find line number for package %s in section %s of %s", name, section, path)
			loc = extractor.LocationFromPath(path)
		}

		groupSlice := []string{}
		if group != "" {
			groupSlice = []string{group}
		}

		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypePyPi,
			Location: loc,
			Metadata: &osv.DepGroupMetadata{
				DepGroupVals: groupSlice,
			},
		})
	}
	return packages
}

// versionSpec returns the version-specifier string for a Pipfile entry and
// whether the entry is supported. String values are always supported. Inline
// tables are supported only when they contain a "version" key; VCS, editable,
// and local-path tables (no "version") are not supported.
func versionSpec(val any) (string, bool) {
	switch v := val.(type) {
	case string:
		return v, true
	case map[string]any:
		ver, ok := v["version"]
		if !ok {
			return "", false
		}
		s, ok := ver.(string)
		if !ok {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}

// extractVersion returns the concrete version for exact pins (==X.Y.Z) and
// simple single-comparator constraints (>=X, <=X, >X, <X, ~=X, ===X), per the
// issue spec: "Preserve version/comparator metadata only for exact pins and
// simple single-comparator constraints". Wildcards and compound constraints
// (",") do not identify one version and return an empty string.
func extractVersion(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return ""
	}
	if strings.ContainsAny(spec, ",*") {
		return ""
	}
	for _, p := range []string{"===", "==", ">=", "<=", "~=", ">", "<"} {
		if v, ok := strings.CutPrefix(spec, p); ok {
			v = strings.TrimSpace(v)
			if v == "" {
				return ""
			}
			return v
		}
	}
	return ""
}

// findPackageLine scans the TOML content for the line number of a package key
// within the given section. Returns 0 if not found.
func findPackageLine(content []byte, section, pkgName string) int {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0
	inSection := false
	sectionHeader := "[" + section + "]"

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") {
			inSection = line == sectionHeader
			continue
		}

		if !inSection {
			continue
		}

		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		if key == pkgName {
			return lineNum
		}
	}
	return 0
}
