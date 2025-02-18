// Copyright 2025 Google LLC
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

// Package npm provides the manifest parsing and writing for the npm package.json format.
package npm

import (
	"encoding/json"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest"
	"github.com/google/osv-scalibr/log"
)

// RequirementKey is a comparable type that uniquely identifies a package dependency in a manifest.
type RequirementKey struct {
	resolve.PackageKey
	KnownAs string
}

var _ map[RequirementKey]any

// MakeRequirementKey constructs an npm RequirementKey from the given RequirementVersion.
func MakeRequirementKey(requirement resolve.RequirementVersion) manifest.RequirementKey {
	// Npm requirements are the uniquely identified by the key in the dependencies fields (which ends up being the path in node_modules)
	// Declaring a dependency in multiple places (dependencies, devDependencies, optionalDependencies) only installs it once at one version.
	// Aliases & non-registry dependencies are keyed on their 'KnownAs' attribute.
	knownAs, _ := requirement.Type.GetAttr(dep.KnownAs)
	return RequirementKey{
		PackageKey: requirement.PackageKey,
		KnownAs:    knownAs,
	}
}

type npmManifest struct {
	filePath       string
	root           resolve.Version
	requirements   []resolve.RequirementVersion
	groups         map[manifest.RequirementKey][]string
	localManifests []*npmManifest
}

// FilePath returns the path to the manifest file.
func (m *npmManifest) FilePath() string {
	return m.filePath
}

// Root returns the Version representing this package.
func (m *npmManifest) Root() resolve.Version {
	return m.root
}

// System returns the ecosystem of this manifest.
func (m *npmManifest) System() resolve.System {
	return resolve.NPM
}

// Requirements returns all direct requirements (including dev).
func (m *npmManifest) Requirements() []resolve.RequirementVersion {
	return m.requirements
}

// Groups returns the dependency groups that the direct requirements belong to.
func (m *npmManifest) Groups() map[manifest.RequirementKey][]string {
	return m.groups
}

// LocalManifests returns Manifests of any local packages.
func (m *npmManifest) LocalManifests() []manifest.Manifest {
	locals := make([]manifest.Manifest, len(m.localManifests))
	for i, l := range m.localManifests {
		locals[i] = l
	}
	return locals
}

// EcosystemSpecific returns any ecosystem-specific information for this manifest.
func (m *npmManifest) EcosystemSpecific() any {
	return nil
}

// Clone returns a copy of this manifest that is safe to modify.
func (m *npmManifest) Clone() manifest.Manifest {
	clone := &npmManifest{
		filePath:     m.filePath,
		root:         m.root,
		requirements: slices.Clone(m.requirements),
		groups:       maps.Clone(m.groups),
	}
	clone.root.AttrSet = m.root.AttrSet.Clone()
	clone.localManifests = make([]*npmManifest, len(m.localManifests))
	for i, local := range m.localManifests {
		clone.localManifests[i] = local.Clone().(*npmManifest)
	}

	return clone
}

type readWriter struct{}

// GetReadWriter returns a ReadWriter for package.json manifest files.
// registry is unused.
func GetReadWriter(registry string) (manifest.ReadWriter, error) {
	return readWriter{}, nil
}

// System returns the ecosystem of this ReadWriter.
func (r readWriter) System() resolve.System {
	return resolve.NPM
}

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Workspaces           []string          `json:"workspaces"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// Read parses the manifest from the given file.
func (r readWriter) Read(path string, fsys scalibrfs.FS) (manifest.Manifest, error) {
	return parse(path, fsys, true)
}

func parse(path string, fsys scalibrfs.FS, doWorkspaces bool) (*npmManifest, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	var pkgJSON packageJSON
	if err := dec.Decode(&pkgJSON); err != nil {
		return nil, err
	}

	// Create the root node.
	manif := &npmManifest{
		filePath: path,
		root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.NPM,
					Name:   pkgJSON.Name,
				},
				VersionType: resolve.Concrete,
				Version:     pkgJSON.Version,
			},
		},
		groups: make(map[manifest.RequirementKey][]string),
	}

	workspaceNames := make(map[string]struct{})
	if doWorkspaces {
		// Find all package.json files in the workspaces & parse those too.
		var workspaces []string
		for _, pattern := range pkgJSON.Workspaces {
			match, err := fs.Glob(fsys, filepath.Join(filepath.Dir(path), pattern, "package.json"))
			if err != nil {
				return nil, err
			}
			workspaces = append(workspaces, match...)
		}

		// workspaces seem to be evaluated in sorted path order
		slices.Sort(workspaces)
		for _, path := range workspaces {
			m, err := parse(path, fsys, false) // workspaces cannot have their own workspaces.
			if err != nil {
				return nil, err
			}
			manif.localManifests = append(manif.localManifests, m)
			workspaceNames[m.root.Name] = struct{}{}
		}
	}

	isWorkspace := func(req resolve.RequirementVersion) bool {
		if req.Type.HasAttr(dep.KnownAs) {
			// "alias": "npm:pkg@*" seems to always take the real 'pkg',
			// even if there's a workspace with the same name.
			return false
		}
		_, ok := workspaceNames[req.Name]

		return ok
	}

	workspaceReqVers := make(map[resolve.PackageKey]resolve.RequirementVersion)

	// empirically, the dev version takes precedence over optional, which takes precedence over regular, if they conflict.
	for pkg, ver := range pkgJSON.Dependencies {
		req, ok := makeNPMReqVer(pkg, ver)
		if !ok {
			log.Warnf("Skipping unsupported requirement: \"%s\": \"%s\"", pkg, ver)
			continue
		}
		if isWorkspace(req) {
			// workspaces seem to always be evaluated separately
			workspaceReqVers[req.PackageKey] = req
			continue
		}
		manif.requirements = append(manif.requirements, req)
	}

	for pkg, ver := range pkgJSON.OptionalDependencies {
		req, ok := makeNPMReqVer(pkg, ver)
		if !ok {
			log.Warnf("Skipping unsupported requirement: \"%s\": \"%s\"", pkg, ver)
			continue
		}
		req.Type.AddAttr(dep.Opt, "")
		if isWorkspace(req) {
			// workspaces seem to always be evaluated separately
			workspaceReqVers[req.PackageKey] = req
			continue
		}
		idx := slices.IndexFunc(manif.requirements, func(imp resolve.RequirementVersion) bool {
			return imp.PackageKey == req.PackageKey
		})
		if idx != -1 {
			manif.requirements[idx] = req
		} else {
			manif.requirements = append(manif.requirements, req)
		}
		manif.groups[MakeRequirementKey(req)] = []string{"optional"}
	}

	for pkg, ver := range pkgJSON.DevDependencies {
		req, ok := makeNPMReqVer(pkg, ver)
		if !ok {
			log.Warnf("Skipping unsupported requirement: \"%s\": \"%s\"", pkg, ver)
			continue
		}
		if isWorkspace(req) {
			// workspaces seem to always be evaluated separately
			workspaceReqVers[req.PackageKey] = req
			continue
		}
		idx := slices.IndexFunc(manif.requirements, func(imp resolve.RequirementVersion) bool {
			return imp.PackageKey == req.PackageKey
		})
		if idx != -1 {
			// In newer versions of npm, having a package in both the `dependencies` and `devDependencies`
			// makes it treated as ONLY a devDependency (using the devDependency version)
			// npm v6 and below seems to do the opposite and there's no easy way of seeing the npm version...
			manif.requirements[idx] = req
		} else {
			manif.requirements = append(manif.requirements, req)
		}
		manif.groups[MakeRequirementKey(req)] = []string{"dev"}
	}

	resolve.SortDependencies(manif.requirements)

	// resolve workspaces after regular requirements
	for i, m := range manif.localManifests {
		imp, ok := workspaceReqVers[m.root.PackageKey]
		if !ok { // The workspace isn't directly used by the root package, add it as a 'requirement' anyway so it's resolved
			imp = resolve.RequirementVersion{
				Type: dep.NewType(),
				VersionKey: resolve.VersionKey{
					PackageKey:  m.root.PackageKey,
					Version:     "*", // use the 'any' specifier so we always match the sub-package version
					VersionType: resolve.Requirement,
				},
			}
		}
		// Add an extra identifier to the workspace package names so name collisions don't overwrite indirect dependencies
		imp.Name += ":workspace"
		manif.localManifests[i].root.Name = imp.Name
		manif.requirements = append(manif.requirements, imp)
		// replace the workspace's sibling requirements
		for j, req := range m.requirements {
			if isWorkspace(req) {
				manif.localManifests[i].requirements[j].Name = req.Name + ":workspace"
				reqKey := MakeRequirementKey(req)
				if g, ok := m.groups[reqKey]; ok {
					newKey := MakeRequirementKey(manif.localManifests[i].requirements[j])
					manif.localManifests[i].groups[newKey] = g
					delete(manif.localManifests[i].groups, reqKey)
				}
			}
		}
	}

	return manif, nil
}

func makeNPMReqVer(pkg, ver string) (resolve.RequirementVersion, bool) {
	typ := dep.NewType() // don't use dep.NewType(dep.Dev) for devDeps to force the resolver to resolve them
	realPkg, realVer := SplitNPMAlias(ver)
	if realPkg != "" {
		// This dependency is aliased, add it as a
		// dependency on the actual name, with the
		// KnownAs attribute set to the alias.
		typ.AddAttr(dep.KnownAs, pkg)
		pkg = realPkg
		ver = realVer
	}
	if strings.ContainsAny(ver, ":/") {
		// Skip non-registry dependencies
		// e.g. `git+https://...`, `file:...`, `github-user/repo`
		return resolve.RequirementVersion{}, false
	}

	return resolve.RequirementVersion{
		Type: typ,
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				Name:   pkg,
				System: resolve.NPM,
			},
			Version:     ver,
			VersionType: resolve.Requirement,
		},
	}, true
}

// SplitNPMAlias extracts the real package name and version from an alias-specified version.
//
// e.g. "npm:pkg@^1.2.3" -> name: "pkg", version: "^1.2.3"
//
// If the version is not an alias specifier, the name will be empty and the version unchanged.
func SplitNPMAlias(v string) (name, version string) {
	if r, ok := strings.CutPrefix(v, "npm:"); ok {
		if i := strings.LastIndex(r, "@"); i > 0 {
			return r[:i], r[i+1:]
		}

		return r, "" // alias with no version specified
	}

	return "", v // not an alias
}
