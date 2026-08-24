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

// Package bunlock extracts bun.lock files
package bunlock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/depgraph"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/linefinder"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/tidwall/gjson"
	"github.com/tidwall/jsonc"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/bunlock"
)

type bunWorkspace struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type bunLockfile struct {
	Version    int                     `json:"lockfileVersion"`
	Workspaces map[string]bunWorkspace `json:"workspaces"`
	Packages   map[string][]any        `json:"packages"`
}

// Extractor extracts npm packages from bun.lock files.
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

// FileRequired returns true if the specified file matches bun lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "bun.lock" {
		return false
	}
	// Skip lockfiles inside node_modules directories since the packages they list aren't
	// necessarily installed by the root project. We instead use the more specific top-level
	// lockfile for the root project dependencies.
	dir := filepath.ToSlash(filepath.Dir(path))
	return !slices.Contains(strings.Split(dir, "/"), "node_modules")
}

// structurePackageDetails returns the name, version, and commit of a package
// specified as a tuple in a bun.lock
func structurePackageDetails(pkgs []any) (string, string, string, error) {
	if len(pkgs) == 0 {
		return "", "", "", errors.New("empty package tuple")
	}

	str, ok := pkgs[0].(string)

	if !ok {
		return "", "", "", errors.New("first element of package tuple is not a string")
	}

	str, isScoped := strings.CutPrefix(str, "@")
	name, version, _ := strings.Cut(str, "@")

	if isScoped {
		name = "@" + name
	}

	version, commit, _ := strings.Cut(version, "#")

	// bun.lock does not track both the commit and version,
	// so if we have a commit then we don't have a version
	if commit != "" {
		version = ""
	}

	// file and workspace dependencies do not have a semantic version recorded
	if strings.HasPrefix(version, "file:") || strings.HasPrefix(version, "workspace:") {
		version = ""
	}

	return name, version, commit, nil
}

// packageDependencies returns the dependency name->range maps from a package
// tuple. The metadata object's index varies by package kind (2 for registry
// packages, 1 for file/git/workspace packages), so we take the first map
// element after the spec string.
func packageDependencies(pkgs []any) (deps, optionalDeps, peerDeps map[string]string) {
	for _, elem := range pkgs[1:] {
		if meta, ok := elem.(map[string]any); ok {
			return stringMap(meta, "dependencies"), stringMap(meta, "optionalDependencies"), stringMap(meta, "peerDependencies")
		}
	}
	return nil, nil, nil
}

func stringMap(meta map[string]any, key string) map[string]string {
	obj, ok := meta[key].(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string]string, len(obj))
	for k, v := range obj {
		if s, ok := v.(string); ok {
			result[k] = s
		}
	}
	return result
}

// resolveDepKey resolves dependency depName of the package at lockfile key
// pkgKey to the key of the installed instance, following npm-style nesting:
// "a/b" + "c" tries "a/b/c", "a/c", then "c".
func resolveDepKey(pkgKey, depName string, keys map[string]bool) (string, bool) {
	prefix := pkgKey
	for {
		candidate := depName
		if prefix != "" {
			candidate = prefix + "/" + depName
		}
		if candidate != pkgKey && keys[candidate] {
			return candidate, true
		}
		if prefix == "" {
			return "", false
		}
		prefix = stripLastInstallName(prefix)
	}
}

// stripLastInstallName removes the last install-name segment from a
// "/"-joined key prefix. A scoped name ("@scope/name") is a single segment.
func stripLastInstallName(prefix string) string {
	i := strings.LastIndex(prefix, "/")
	if i == -1 {
		return ""
	}
	head := prefix[:i]
	j := strings.LastIndex(head, "/")
	if strings.HasPrefix(head[j+1:], "@") {
		if j == -1 {
			return ""
		}
		return head[:j]
	}
	return head
}

// depEdges drops dependency names that resolve to no lockfile key.
func depEdges(parent *extractor.Package, baseKey string, keySet map[string]bool, pkgByKey map[string]*extractor.Package, depMaps ...map[string]string) []depgraph.Edge {
	var edges []depgraph.Edge
	for _, m := range depMaps {
		for _, depName := range slices.Sorted(maps.Keys(m)) {
			if childKey, ok := resolveDepKey(baseKey, depName, keySet); ok {
				edges = append(edges, depgraph.Edge{Parent: parent, Child: pkgByKey[childKey]})
			}
		}
	}
	return edges
}

// Extract extracts packages from bun.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *bunLockfile

	b, err := io.ReadAll(input.Reader)

	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	if err := json.Unmarshal(jsonc.ToJSON(b), &parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract %w", err)
	}

	finder := linefinder.NewJSONLineFinder(b)
	keys := slices.Sorted(maps.Keys(parsedLockfile.Packages))
	packages := make([]*extractor.Package, 0, len(keys))
	pkgByKey := make(map[string]*extractor.Package, len(keys))
	keySet := make(map[string]bool, len(keys))

	var errs []error

	for _, key := range keys {
		name, version, commit, err := structurePackageDetails(parsedLockfile.Packages[key])

		if err != nil {
			errs = append(errs, fmt.Errorf("could not extract '%s': %w", key, err))

			continue
		}

		lineNum := finder.LineOf("packages." + gjson.Escape(key))
		pkg := &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeNPM,
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
			},
			Metadata: &osv.DepGroupMetadata{
				DepGroupVals: []string{},
			},
			Location: extractor.LocationFromPathAndLine(input.Path, lineNum),
		}
		packages = append(packages, pkg)
		pkgByKey[key] = pkg
		keySet[key] = true
	}

	edges := getDependencyEdges(parsedLockfile, keys, pkgByKey, keySet)
	if err := depgraph.ApplyEdges(packages, edges); err != nil {
		errs = append(errs, err)
	}

	return inventory.Inventory{Packages: packages}, errors.Join(errs...)
}

// getDependencyEdges can emit duplicate edges; ParentIDs is a set.
func getDependencyEdges(lockfile *bunLockfile, keys []string, pkgByKey map[string]*extractor.Package, keySet map[string]bool) []depgraph.Edge {
	var edges []depgraph.Edge
	for _, key := range keys {
		parent, ok := pkgByKey[key]
		if !ok {
			continue
		}
		deps, optionalDeps, peerDeps := packageDependencies(lockfile.Packages[key])
		edges = append(edges, depEdges(parent, key, keySet, pkgByKey, deps, optionalDeps, peerDeps)...)
	}

	for _, wsPath := range slices.Sorted(maps.Keys(lockfile.Workspaces)) {
		ws := lockfile.Workspaces[wsPath]
		var parent *extractor.Package
		baseKey := ""
		if wsPath != "" {
			if member, ok := pkgByKey[ws.Name]; ok {
				edges = append(edges, depgraph.Edge{Child: member})
				parent = member
				baseKey = ws.Name
			}
		}
		edges = append(edges, depEdges(parent, baseKey, keySet, pkgByKey,
			ws.Dependencies, ws.DevDependencies, ws.OptionalDependencies, ws.PeerDependencies)...)
	}
	return edges
}
