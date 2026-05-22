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

// Package denolock extracts deno.lock files.
package denolock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/denolock"
)

// denoLockfile models the subset of the deno.lock format that lists resolved
// packages. The npm and jsr maps are keyed by "name@version" entries.
//
// Lockfile v4 and v5 expose the npm and jsr sections at the top level, while v3
// nests them under "packages". We read both so the extractor works across these
// versions.
type denoLockfile struct {
	Version  string            `json:"version"`
	JSR      map[string]any    `json:"jsr"`
	NPM      map[string]any    `json:"npm"`
	Packages *denoLockPackages `json:"packages"`
}

type denoLockPackages struct {
	JSR map[string]any `json:"jsr"`
	NPM map[string]any `json:"npm"`
}

// Extractor extracts npm and jsr packages from deno.lock files.
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

// FileRequired returns true if the specified file matches the deno.lock pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "deno.lock" {
		return false
	}
	// Skip lockfiles inside node_modules directories since the packages they list
	// aren't necessarily installed by the root project. We instead rely on the
	// top-level lockfile for the root project dependencies.
	dir := filepath.ToSlash(filepath.Dir(path))
	return !slices.Contains(strings.Split(dir, "/"), "node_modules")
}

// Extract extracts packages from deno.lock files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	var parsedLockfile denoLockfile
	if err := json.Unmarshal(b, &parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	npm := parsedLockfile.NPM
	jsr := parsedLockfile.JSR
	if parsedLockfile.Packages != nil {
		npm = mergeMaps(npm, parsedLockfile.Packages.NPM)
		jsr = mergeMaps(jsr, parsedLockfile.Packages.JSR)
	}

	packages := make([]*extractor.Package, 0, len(npm)+len(jsr))
	packages = appendPackages(packages, npm, purl.TypeNPM, input.Path)
	packages = appendPackages(packages, jsr, purl.TypeJSR, input.Path)

	return inventory.Inventory{Packages: packages}, nil
}

// appendPackages parses every "name@version" key in entries and appends the
// resulting packages, tagging them with the given PURL type.
func appendPackages(packages []*extractor.Package, entries map[string]any, purlType, path string) []*extractor.Package {
	for key := range entries {
		name, version := parsePackageKey(key)
		if name == "" || version == "" {
			log.Debugf("deno.lock skipping unparsable package key %q", key)
			continue
		}
		// jsr scoped names drop the leading "@" to stay consistent with the other
		// Deno extractors (e.g. "@std/internal" -> "std/internal"), while npm names
		// keep their scope prefix (e.g. "@babel/core").
		if purlType == purl.TypeJSR {
			name = strings.TrimPrefix(name, "@")
		}
		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purlType,
			Location: extractor.LocationFromPath(path),
		})
	}
	return packages
}

// parsePackageKey splits a deno.lock package key into its name and version.
//
// Keys take the form "name@version", where the name may be scoped (for example
// "@std/path@1.0.8") and the version may carry a peer-dependency suffix that
// Deno appends after an underscore (for example "debug@4.3.4_supports-color@8.1.1").
func parsePackageKey(key string) (name, version string) {
	rest := key
	scopePrefix := ""
	if strings.HasPrefix(key, "@") {
		// Scoped name: the version separator is the "@" after the scope's "/".
		slash := strings.Index(key, "/")
		if slash == -1 {
			return "", ""
		}
		scopePrefix = key[:slash+1]
		rest = key[slash+1:]
	}

	at := strings.Index(rest, "@")
	if at <= 0 {
		return "", ""
	}
	name = scopePrefix + rest[:at]
	version = rest[at+1:]

	// Drop the peer-dependency suffix; a resolved semver never contains "_".
	if i := strings.Index(version, "_"); i != -1 {
		version = version[:i]
	}
	return name, version
}

// mergeMaps returns a map containing all entries from a and b. Keys in b take
// precedence on collision.
func mergeMaps(a, b map[string]any) map[string]any {
	if len(b) == 0 {
		return a
	}
	merged := make(map[string]any, len(a)+len(b))
	maps.Copy(merged, a)
	maps.Copy(merged, b)
	return merged
}
