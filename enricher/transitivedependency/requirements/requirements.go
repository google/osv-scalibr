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

// Package requirements implements an enricher to perform dependency resolution for Python requirements.txt.
package requirements

import (
	"context"
	"errors"
	"slices"

	"deps.dev/util/pypi"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	pypiresolve "deps.dev/util/resolve/pypi"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/transitivedependency/internal"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this enricher.
	Name = "transitivedependency/requirements"
)

// Enricher performs dependency resolution for requirements.txt.
type Enricher struct {
	resolve.Client
}

// Name returns the name of the enricher.
func (Enricher) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (Enricher) Version() int {
	return 0
}

// Requirements returns the requirements of the enricher.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// RequiredPlugins returns the names of the plugins required by the enricher.
func (Enricher) RequiredPlugins() []string {
	return []string{requirements.Name}
}

// New creates a new Enricher.
func New(cfg *cpb.PluginConfig) (enricher.Enricher, error) {
	return &Enricher{
		// Empty remote registry indicates using the default PyPI registry.
		Client: resolution.NewPyPIRegistryClient("", cfg.LocalRegistry),
	}, nil
}

// Enrich enriches the inventory in requirements.txt with transitive dependencies.
func (e Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	pkgGroups := internal.GroupPackagesFromPlugin(inv.Packages, requirements.Name)
	for path, pkgMap := range pkgGroups {
		packages := make([]internal.PackageWithIndex, 0, len(pkgMap))
		for _, indexPkg := range pkgMap {
			packages = append(packages, indexPkg)
		}
		slices.SortFunc(packages, func(a, b internal.PackageWithIndex) int {
			return a.Index - b.Index
		})

		list := make([]*extractor.Package, 0, len(packages))
		for _, indexPkg := range packages {
			list = append(list, indexPkg.Pkg)
		}
		if len(list) == 0 || len(list[0].Metadata.(*requirements.Metadata).HashCheckingModeValues) > 0 {
			// Do not perform transitive extraction with hash-checking mode.
			// Hash-checking is an all-or-nothing proposition so we can assume the
			// requirements is in hash-checking mode if the first package has hashes.
			// https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode
			continue
		}

		// For each manifest, perform dependency resolution.
		pkgs, err := e.resolve(ctx, path, list)
		if err != nil {
			log.Warnf("failed resolution: %v", err)
			continue
		}

		for _, pkg := range pkgs {
			indexPkg, ok := pkgMap[pkg.Name]
			if ok {
				// This dependency is in manifest, update the version and plugins.
				i := indexPkg.Index
				inv.Packages[i].Version = pkg.Version
				inv.Packages[i].Plugins = append(inv.Packages[i].Plugins, Name)
			} else {
				// This dependency is not found in manifest, so it's a transitive dependency.
				inv.Packages = append(inv.Packages, pkg)
			}
		}
	}
	return nil
}

// resolve performs dependency resolution for packages found in a single requirements.txt.
func (e Enricher) resolve(ctx context.Context, path string, list []*extractor.Package) ([]*extractor.Package, error) {
	overrideClient := resolution.NewOverrideClient(e.Client)
	resolver := pypiresolve.NewResolver(overrideClient)

	// Resolve the dependencies.
	root := resolve.Version{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.PyPI,
				// Name of root node does not matter
			},
			VersionType: resolve.Concrete,
			// Version of root node does not matter
		}}
	reqs := make([]resolve.RequirementVersion, len(list))
	for i, pkg := range list {
		m := pkg.Metadata.(*requirements.Metadata)
		d, err := pypi.ParseDependency(m.Requirement)
		if err != nil {
			log.Errorf("failed to parse requirement %s: %v", m.Requirement, err)
			continue
		}

		t := dep.NewType()
		if d.Extras != "" {
			t.AddAttr(dep.EnabledDependencies, d.Extras)
		}
		if d.Environment != "" {
			t.AddAttr(dep.Environment, d.Environment)
		}

		reqs[i] = resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   d.Name,
				},
				VersionType: resolve.Requirement,
				Version:     d.Constraint,
			},
			Type: t,
		}
	}
	overrideClient.AddVersion(root, reqs)

	g, err := resolver.Resolve(ctx, root.VersionKey)
	if err != nil {
		return nil, err
	}
	if g.Error != "" {
		return nil, errors.New(g.Error)
	}

	pkgs := make([]*extractor.Package, len(g.Nodes)-1)
	for i := 1; i < len(g.Nodes); i++ {
		// Ignore the first node which is the root.
		node := g.Nodes[i]
		pkgs[i-1] = &extractor.Package{
			Name:      node.Version.Name,
			Version:   node.Version.Version,
			PURLType:  purl.TypePyPi,
			Locations: []string{path},
			Plugins:   []string{Name},
		}
	}
	return pkgs, nil
}
