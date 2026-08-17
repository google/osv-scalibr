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

// Package pipfile implements an enricher to perform dependency resolution for Python Pipfile.
package pipfile

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"deps.dev/util/pypi"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	pypiresolve "deps.dev/util/resolve/pypi"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/depsdev"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/transitivedependency/internal"
	"github.com/google/osv-scalibr/extractor"
	extractorpipfile "github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this enricher.
	Name = "transitivedependency/pipfile"
)

// Enricher performs dependency resolution for Pipfile.
type Enricher struct {
	resolve.Client
}

// Name returns the name of the enricher.
func (Enricher) Name() string { return Name }

// Version returns the version of the enricher.
func (Enricher) Version() int { return 0 }

// Requirements returns the requirements of the enricher.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// RequiredPlugins returns the names of the plugins required by the enricher.
func (Enricher) RequiredPlugins() []string {
	return []string{extractorpipfile.Name}
}

// New creates a new Enricher.
func New(cfg *config.PluginConfig) (enricher.Enricher, error) {
	if cfg == nil || cfg.ClientFactories == nil {
		return nil, fmt.Errorf("client factories not configured for %s", Name)
	}

	upstreamRegistry := ""
	depsDevRequirements := false
	var protoCfg *cpb.PluginConfig
	localRegistry := ""
	if cfg.ProtoConfig != nil {
		protoCfg = cfg.ProtoConfig
		localRegistry = cfg.ProtoConfig.LocalRegistry
	}
	specific := plugin.FindConfig(protoCfg, func(c *cpb.PluginSpecificConfig) *cpb.PythonRequirementsTransitiveConfig {
		return c.GetPythonRequirementsTransitive()
	})
	if specific != nil {
		upstreamRegistry = specific.UpstreamRegistry
		depsDevRequirements = specific.DepsDevRequirements
	}

	var depClient resolve.Client
	var err error
	if depsDevRequirements {
		conn, err := cfg.ClientFactories.GRPCClientConn(depsdev.DepsdevAPI)
		if err != nil {
			return nil, err
		}
		depClient = resolution.NewDepsDevClientWithConn(conn)
	} else {
		depClient, err = resolution.NewPyPIRegistryClient(upstreamRegistry, localRegistry, cfg.ClientFactories.HTTPClient())
		if err != nil {
			return nil, err
		}
	}

	return &Enricher{
		Client: depClient,
	}, nil
}

// Enrich enriches the inventory from Pipfile with transitive dependencies.
func (e Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	pkgGroups := internal.GroupPackagesFromPlugin(inv.Packages, extractorpipfile.Name)
	paths := make([]string, 0, len(pkgGroups))
	for p := range pkgGroups {
		paths = append(paths, p)
	}
	slices.Sort(paths)

	var errs error
	for _, path := range paths {
		pkgMap := pkgGroups[path]
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

		scanRoot := ""
		if input.ScanRoot != nil {
			scanRoot = input.ScanRoot.Path
		}

		pkgs, err := e.resolve(ctx, path, scanRoot, list)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("resolving %s: %w", path, err))
			continue
		}
		inv.Packages = append(inv.Packages, pkgs...)
	}
	return errs
}

func (e Enricher) resolve(ctx context.Context, path, scanRoot string, list []*extractor.Package) ([]*extractor.Package, error) {
	overrideClient := resolution.NewOverrideClient(e.Client)
	resolver := pypiresolve.NewResolver(overrideClient)

	root := resolve.Version{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.PyPI,
			},
			VersionType: resolve.Concrete,
		}}

	reqs := make([]resolve.RequirementVersion, len(list))
	for i, pkg := range list {
		m, ok := pkg.Metadata.(*extractorpipfile.Metadata)
		if !ok {
			log.Errorf("unexpected metadata type for Pipfile package %s", pkg.Name)
			continue
		}
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

	nameToID, err := internal.GetNameToIDMapping(g, list)
	if err != nil {
		return nil, err
	}

	pkgs := make([]*extractor.Package, len(g.Nodes)-1)
	for i := 1; i < len(g.Nodes); i++ {
		node := g.Nodes[i]

		parents, err := internal.GetParentIDs(g, nameToID, resolve.NodeID(i))
		if err != nil {
			return nil, err
		}

		pkgs[i-1] = &extractor.Package{
			ID:        nameToID[node.Version.Name],
			Name:      node.Version.Name,
			ParentIDs: parents,
			Version:   node.Version.Version,
			PURLType:  purl.TypePyPi,
			ScanRoot:  scanRoot,
			Location:  extractor.LocationFromPath(path),
			Plugins:   []string{Name},
		}
	}

	// Sort for deterministic output (mirrors requirements enricher pattern).
	slices.SortFunc(pkgs, func(a, b *extractor.Package) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return pkgs, nil
}
