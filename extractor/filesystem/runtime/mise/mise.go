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

// Package mise extracts the installed runtime names and versions from mise.toml files.
package mise

import (
	"context"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	misemeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/mise/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "runtime/mise"
)

// Extractor extracts mise tools.
type Extractor struct{}

// miseTomlFile represents the structure of a mise.toml file.
type miseTomlFile struct {
	Tools map[string]any `toml:"tools"`
}

// New returns a new instance of the extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file matches any of the mise config file paths.
// Supported paths (in order of precedence):
//   - mise.local.toml (local config, should not be committed)
//   - .config/mise.toml
//   - mise.toml
//   - mise/config.toml
//   - .mise/config.toml
//   - .config/mise/config.toml
//   - .config/mise/conf.d/*.toml
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := path.Base(api.Path())
	dir := path.Dir(api.Path())

	// Check for mise.local.toml in any directory
	if base == "mise.local.toml" {
		return true
	}

	// Check for .config/mise.toml
	if base == "mise.toml" && path.Base(dir) == ".config" {
		return true
	}

	// Check for mise.toml in any directory (except .config, which is handled above)
	if base == "mise.toml" {
		return true
	}

	// Check for mise/config.toml
	if base == "config.toml" && path.Base(dir) == "mise" {
		return true
	}

	// Check for .mise/config.toml
	if base == "config.toml" && path.Base(dir) == ".mise" {
		return true
	}

	// Check for .config/mise/config.toml
	if base == "config.toml" && strings.HasSuffix(dir, ".config/mise") {
		return true
	}

	// Check for .config/mise/conf.d/*.toml
	if path.Ext(base) == ".toml" && strings.HasSuffix(dir, ".config/mise/conf.d") {
		return true
	}

	return false
}

// Extract extracts packages from the mise.toml file.
//
// Reference: https://mise.jdx.dev/configuration.html
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedTomlFile miseTomlFile
	_, err := toml.NewDecoder(input.Reader).Decode(&parsedTomlFile)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	var pkgs []*extractor.Package
	for _, tool := range slices.Sorted(maps.Keys(parsedTomlFile.Tools)) {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		name, ok := normalizeToolName(tool)
		if !ok {
			continue
		}

		for _, rawVersion := range extractRawVersions(parsedTomlFile.Tools[tool]) {
			version, ok := normalizeVersion(rawVersion)
			if !ok {
				continue
			}

			pkgs = append(pkgs, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeGeneric,
				Location: extractor.LocationFromPath(input.Path),
				Metadata: &misemeta.Metadata{
					ToolName:    tool,
					ToolVersion: rawVersion,
				},
			})
		}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

func normalizeToolName(tool string) (string, bool) {
	tool = strings.ToLower(strings.TrimSpace(tool))
	if prefix, rest, hasColon := strings.Cut(tool, ":"); hasColon {
		switch prefix {
		case "core", "asdf", "vfox":
			tool = rest
		default:
			// Skip non-runtime package or URL backends (e.g., npm:, cargo:, pipx:, github:).
			return "", false
		}
	}
	// Skip empty names and custom plugin repo/URL or option specs (e.g., asdf:owner/repo, node[opt=val]).
	if tool == "" || strings.ContainsAny(tool, ":/@[] \t\r\n") {
		return "", false
	}
	switch tool {
	case "node":
		return "nodejs", true
	case "py":
		return "python", true
	case "go":
		return "golang", true
	default:
		return tool, true
	}
}

func extractRawVersions(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case map[string]any:
		return extractRawVersions(v["version"])
	case []map[string]any:
		var out []string
		for _, elem := range v {
			out = append(out, extractRawVersions(elem["version"])...)
		}
		return out
	case []any:
		var out []string
		for _, elem := range v {
			out = append(out, extractRawVersions(elem)...)
		}
		return out
	default:
		return nil
	}
}

func normalizeVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	// Skip non-numeric aliases (e.g., "system", "latest", "nightly"), path/ref/prefix
	// directives (e.g., "path:/opt/go", "ref:v1.0.0", "prefix:20.11"), and semver
	// range constraints or whitespace-separated expressions (e.g., "^20.12.0", ">= 1.21").
	if !strings.ContainsAny(v, "0123456789") ||
		strings.ContainsAny(v, ":/^~*<>|= \t\r\n") {
		return "", false
	}
	// Skip unpinned channel, git ref, subtraction, or wildcard prefixes/suffixes
	// (e.g., "lts-iron", "ref-main", "sub-0.1:22", "miniconda3-latest", "20.x").
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "lts-") ||
		strings.HasPrefix(lower, "ref-") ||
		strings.HasPrefix(lower, "sub-") ||
		strings.HasSuffix(lower, "-latest") ||
		strings.HasSuffix(lower, ".x") {
		return "", false
	}
	if len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return v, true
}
