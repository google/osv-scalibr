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

// Package license contains an Enricher that adds license data
// to software packages by querying deps.dev
package license

import (
	"context"
	"fmt"

	depsdevpb "deps.dev/api/v3"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/license/depsdev"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// Name is the unique name of this Enricher.
	Name    = "license/depsdev"
	version = 1
)

const maxConcurrentRequests = 1000

var _ enricher.Enricher = &Enricher{}

// Enricher adds license data to software packages by querying deps.dev
type Enricher struct {
	client *datasource.CachedInsightsClient
}

// NewWithClient returns an Enricher which uses a specified deps.dev client.
func NewWithClient(c *datasource.CachedInsightsClient) enricher.Enricher {
	return &Enricher{client: c}
}

// New creates a new Enricher
func New() enricher.Enricher {
	return &Enricher{}
}

// Name of the Enricher.
func (Enricher) Name() string {
	return Name
}

// Version of the Enricher.
func (Enricher) Version() int {
	return version
}

// Requirements of the Enricher.
// Needs network access so it can validate Secrets.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// RequiredPlugins returns the plugins that are required to be enabled for this
// Enricher to run. While it works on the results of other extractors,
// the Enricher itself can run independently.
func (Enricher) RequiredPlugins() []string {
	return []string{}
}

// Enrich adds license data to all the packages using deps.dev
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	if e.client == nil {
		depsDevAPIClient, err := datasource.NewCachedInsightsClient(depsdev.DepsdevAPI, "osv-scalibr/"+scalibr.ScannerVersion)
		if err != nil {
			return fmt.Errorf("cannot connect with deps.dev %w", err)
		}
		e.client = depsDevAPIClient
	}

	queries := make([]*depsdevpb.GetVersionRequest, 0, len(inv.Packages))

	for _, pkg := range inv.Packages {
		if err := ctx.Err(); err != nil {
			return err
		}

		ecoSystem, ok := depsdev.System[pkg.Ecosystem()]
		if !ok {
			continue
		}
		queries = append(queries, versionQuery(ecoSystem, pkg.Name, pkg.Version))
	}

	licenses, err := e.makeVersionRequest(ctx, queries)
	if err != nil {
		return err
	}

	for i, license := range licenses {
		inv.Packages[i].License = license
	}

	return nil
}

// makeVersionRequest calls the deps.dev GetVersion gRPC API endpoint for each
// query. It makes these requests concurrently, sharing the single HTTP/2
// connection. The order in which the requests are specified should correspond
// to the order of licenses returned by this function.
func (e *Enricher) makeVersionRequest(ctx context.Context, queries []*depsdevpb.GetVersionRequest) ([][]extractor.License, error) {
	licenses := make([][]extractor.License, len(queries))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for i := range queries {
		if queries[i] == nil {
			// This may be a private package.
			licenses[i] = []extractor.License{extractor.License("UNKNOWN")}
			continue
		}
		g.Go(func() error {
			resp, err := e.client.GetVersion(ctx, queries[i])
			if err != nil {
				if status.Code(err) == codes.NotFound {
					licenses[i] = append(licenses[i], "UNKNOWN")
					return nil
				}

				return err
			}
			ls := make([]extractor.License, len(resp.GetLicenses()))
			for j, license := range resp.GetLicenses() {
				ls[j] = extractor.License(license)
			}
			if len(ls) == 0 {
				// The deps.dev API will return an
				// empty slice if the license is
				// unknown.
				ls = []extractor.License{extractor.License("UNKNOWN")}
			}
			licenses[i] = ls

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return licenses, nil
}

func versionQuery(system depsdevpb.System, name string, version string) *depsdevpb.GetVersionRequest {
	if system == depsdevpb.System_GO {
		version = "v" + version
	}

	return &depsdevpb.GetVersionRequest{
		VersionKey: &depsdevpb.VersionKey{
			System:  system,
			Name:    name,
			Version: version,
		},
	}
}
