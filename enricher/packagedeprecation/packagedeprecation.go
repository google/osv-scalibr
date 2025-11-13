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

// Package packagedeprecation enriches inventory details with package version deprecation status from deps.dev
package packagedeprecation

import (
	"context"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/clients/depsdev/v1alpha1/grpcclient"
	"github.com/google/osv-scalibr/depsdev/depsdevalpha"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the name of the package version deprecation enricher.
	Name = "packagedeprecation/depsdev"
)

// Enricher is the package version deprecation enricher.
type Enricher struct {
	// client is the deps.dev GRPC client.
	client Client
}

// Name of the package version deprecation enricher.
func (*Enricher) Name() string { return Name }

// Version of the package version deprecation enricher.
func (*Enricher) Version() int { return 0 }

// Requirements of the package version deprecation enricher.
func (*Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: plugin.NetworkOnline}
}

// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to work.
// While this enricher can run independently,
// it is intended to be used with extractors to provide the inventory data to enrich.
func (*Enricher) RequiredPlugins() []string {
	return []string{}
}

// SetClient sets the deps.dev GRPC client.
// This is used for testing.
func (e *Enricher) SetClient(client Client) {
	e.client = client
}

// New returns a new package deprecation enricher.
func New() enricher.Enricher {
	grpcConfig := grpcclient.DefaultConfig()
	grpcclient, err := grpcclient.New(grpcConfig)
	if err != nil {
		log.Errorf("Failed to create deps.dev gRPC client: %v", err)
	}

	c := NewClient(grpcclient)

	return &Enricher{client: c}
}

// Enrich enriches the inventory with package version deprecation status from deps.dev.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	log.Infof("Package deprecation enricher starting, %d packages to enrich.", len(inv.Packages))

	verToPkg := make(map[VersionKey][]*extractor.Package, len(inv.Packages))

	for _, pkg := range inv.Packages {
		verKey, ok := makeVersionKey(pkg)
		if !ok {
			// System is not supported by deps.dev. Default deprecated to false.
			pkg.Deprecated = false
			continue
		}
		verToPkg[verKey] = append(verToPkg[verKey], pkg)
	}

	if len(verToPkg) == 0 {
		return nil
	}

	query := slices.Collect(maps.Keys(verToPkg))

	resp, err := e.client.GetVersionBatch(ctx, Request{VersionKeys: query})
	if err != nil {
		return err
	}

	results := resp.Results
	for verKey, pkgs := range verToPkg {
		deprecated, ok := results[verKey]
		if !ok {
			// Version key not found in deps.dev. Default deprecated to false.
			for _, pkg := range pkgs {
				pkg.Deprecated = false
			}
			continue
		}
		for _, pkg := range pkgs {
			pkg.Deprecated = deprecated
		}
	}

	log.Infof("Package deprecation enricher finished.")
	return nil
}

// makeVersionKey translates system from PURL type to deps.dev system, and returns a version key.
// Returns false if the system is not supported by deps.dev.
func makeVersionKey(pkg *extractor.Package) (VersionKey, bool) {
	system, ok := depsdevalpha.System[pkg.PURLType]
	if !ok {
		return VersionKey{}, false
	}
	name, ver := pkg.Name, pkg.Version

	// Add "v" prefix for Go versions (except stdlib) to match deps.dev format.
	if pkg.PURLType == purl.TypeGolang && pkg.Name != "stdlib" {
		ver = "v" + ver
	}

	return VersionKey{
		System:  system,
		Name:    name,
		Version: ver,
	}, true
}
