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

// Package asdf extracts the installed runtime names and versions from asdf .tool-versions files.
package asdf

import (
	"bufio"
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	asdfmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/asdf/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "runtime/asdf"
)

// Extractor extracts asdf tools.
type Extractor struct{}

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

// FileRequired returns true if the file name is '.tool-versions'.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == ".tool-versions"
}

// Extract extracts packages from the asdf .tool-versions file.
//
// Reference: https://asdf-vm.com/manage/configuration.html#tool-versions
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)
	var pkgs []*extractor.Package

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		tool, versions, ok := parseToolLine(scanner.Text())
		if !ok {
			continue
		}

		name, ok := normalizeToolName(tool)
		if !ok {
			continue
		}
		for _, rawVersion := range versions {
			version, ok := normalizeVersion(rawVersion)
			if !ok {
				continue
			}
			pkgs = append(pkgs, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeGeneric,
				Location: extractor.LocationFromPath(input.Path),
				Metadata: &asdfmeta.Metadata{
					ToolName:    tool,
					ToolVersion: rawVersion,
				},
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, err
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

func parseToolLine(line string) (tool string, versions []string, ok bool) {
	line, _, _ = strings.Cut(line, "#")
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil, false
	}
	return fields[0], fields[1:], true
}

func normalizeToolName(tool string) (string, bool) {
	tool = strings.ToLower(tool)
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
	if tool == "" || strings.ContainsAny(tool, ":/@[]") {
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

func normalizeVersion(v string) (string, bool) {
	// Skip non-numeric aliases (e.g., "system", "latest", "nightly"), path/ref/prefix
	// directives (e.g., "path:/opt/go", "ref:v1.0.0", "prefix:20.11"), and semver
	// range constraints (e.g., "^20.12.0", ">=1.21").
	if !strings.ContainsAny(v, "0123456789") ||
		strings.ContainsAny(v, ":/^~*<>|=") {
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
