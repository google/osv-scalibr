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

// Package requirementsnet extracts requirements files with .
package requirementsnet

import (
	"context"
	"fmt"

	"deps.dev/util/pypi"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	pypiresolve "deps.dev/util/resolve/pypi"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/requirementsnet"
)

// Config is the configuration for the Extractor.
type Config struct {
	resolve.Client
	// This should be an extractor to extract inventories from requirements.txt offline.
	*requirements.Extractor // Extractor to extract inventories from requirements.txt offline.
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Extractor: requirements.NewDefault().(*requirements.Extractor),
		Client:    resolution.NewPyPIRegistryClient("", ""),
	}
}

// Extractor extracts python packages from requirements.txt files.
type Extractor struct {
	resolve.Client

	BaseExtractor *requirements.Extractor // The base extractor that we use to extract direct dependencies.
}

// New returns a requirements.txt transitive extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		BaseExtractor: cfg.Extractor,
		Client:        cfg.Client,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// FileRequired returns true if the specified file matches python Metadata file
// patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return e.BaseExtractor.FileRequired(api)
}

// Extract extracts packages from requirements files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := e.BaseExtractor.Extract(ctx, input)
	if err != nil {
		return inventory.Inventory{}, err
	}
	if len(inv.Packages) == 0 || len(inv.Packages[0].Metadata.(*requirements.Metadata).HashCheckingModeValues) > 0 {
		// Do not perform transitive extraction with hash-checking mode.
		// Hash-checking is an all-or-nothing proposition so we can assume the
		// requirements is in hash-checking mode if the first package has hashes.
		// https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode
		return inv, nil
	}

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
	reqs := make([]resolve.RequirementVersion, len(inv.Packages))
	for i, pkg := range inv.Packages {
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
		return inventory.Inventory{}, fmt.Errorf("failed resolving: %w", err)
	}
	if g.Error != "" {
		return inventory.Inventory{}, fmt.Errorf("failed resolving: %s", g.Error)
	}

	pkgs := []*extractor.Package{}
	for i := 1; i < len(g.Nodes); i++ {
		// Ignore the first node which is the root.
		node := g.Nodes[i]
		pkgs = append(pkgs, &extractor.Package{
			Name:     node.Version.Name,
			Version:  node.Version.Version,
			PURLType: purl.TypePyPi,
			// TODO(#663): record the path if it's from another requirements file.
			Locations: []string{input.Path},
		})
	}
	inv.Packages = pkgs

	return inv, nil
}
