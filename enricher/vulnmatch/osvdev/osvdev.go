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

// Package osvdev queries the OSV.dev API to find vulnerabilities in the inventory packages
package osvdev

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
	"osv.dev/bindings/go/osvdev"
	"osv.dev/bindings/go/osvdevexperimental"
)

const (
	// Name is the unique name of this Enricher.
	Name    = "vulnmatch/osvdev"
	version = 1
)

const (
	maxConcurrentRequests = 1000
)

// InitialQueryTimeoutErr is returned if the initial query to OSV.dev partially fails due to timeout
var InitialQueryTimeoutErr = errors.New("initialQueryTimeout reached")

var _ enricher.Enricher = &Enricher{}

// Enricher adds license data to software packages by querying deps.dev
type Enricher struct {
	client              *osvdev.OSVClient
	initialQueryTimeout time.Duration
}

// NewWithClient returns an Enricher which uses a specified deps.dev client.
func NewWithClient(c *osvdev.OSVClient, initialQueryTimeout time.Duration) enricher.Enricher {
	return &Enricher{
		client:              c,
		initialQueryTimeout: initialQueryTimeout,
	}
}

// New creates a new Enricher
func New(initialQueryTimeout time.Duration) enricher.Enricher {
	return &Enricher{
		initialQueryTimeout: initialQueryTimeout,
	}
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

// Enrich queries the OSV.dev API to find vulnerabilities in the inventory packages
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	if e.client == nil {
		client := osvdev.DefaultClient()
		// TODO: add better user agent
		// client.Config.UserAgent = "osv-scanner_scan/"+version.OSVVersion
		e.client = client
	}

	pkgs := make([]*extractor.Package, 0, len(inv.Packages))
	queries := make([]*osvdev.Query, 0, len(inv.Packages))
	for _, pkg := range inv.Packages {
		if query := pkgToQuery(pkg); query != nil {
			pkgs = append(pkgs, pkg)
			queries = append(queries, query)
		}
	}

	queryCtx, cancel := withOptionalTimeoutCause(ctx, e.initialQueryTimeout, InitialQueryTimeoutErr)
	batchResp, initialQueryErr := osvdevexperimental.BatchQueryPaging(queryCtx, e.client, queries)
	cancel()

	if initialQueryErr != nil && !errors.Is(InitialQueryTimeoutErr, initialQueryErr) {
		return initialQueryErr
	}

	vulnToPkgs := map[string][]*extractor.Package{}
	for i, batch := range batchResp.Results {
		for _, vv := range batch.Vulns {
			vulnToPkgs[vv.ID] = append(vulnToPkgs[vv.ID], pkgs[i])
		}
	}

	vulnIDs := slices.Collect(maps.Keys(vulnToPkgs))
	vulnerabilities, err := e.makeVulnerabilitiesRequest(ctx, vulnIDs)
	if err != nil {
		return err
	}

	for _, vuln := range vulnerabilities {
		for _, pkg := range vulnToPkgs[vuln.ID] {
			// TODO: dedup inv.PackageVulns in case some were already present
			inv.PackageVulns = append(inv.PackageVulns, &inventory.PackageVuln{
				Vulnerability:         *vuln,
				Package:               pkg,
				ExploitabilitySignals: vex.FindingVEXFromPackageVEX(vuln.ID, pkg.ExploitabilitySignals),
				Plugins:               []string{Name},
			})
		}
	}

	return initialQueryErr
}

func (e *Enricher) makeVulnerabilitiesRequest(ctx context.Context, vulnIDs []string) ([]*osvschema.Vulnerability, error) {
	vulnerabilities := make([]*osvschema.Vulnerability, len(vulnIDs))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for i, vulnID := range vulnIDs {
		g.Go(func() error {
			// exit early if another hydration request has already failed
			// results are thrown away later, so avoid needless work
			if ctx.Err() != nil {
				return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
			}
			vuln, err := e.client.GetVulnByID(ctx, vulnID)
			if err != nil {
				return err
			}
			vulnerabilities[i] = vuln

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return vulnerabilities, nil
}

func pkgToQuery(pkg *extractor.Package) *osvdev.Query {
	if pkg.Name != "" && pkg.Ecosystem() != "" && pkg.Version != "" {
		return &osvdev.Query{
			Package: osvdev.Package{
				Name:      pkg.Name,
				Ecosystem: pkg.Ecosystem(),
			},
			Version: pkg.Version,
		}
	}

	if pkg.SourceCode != nil && pkg.SourceCode.Commit != "" {
		return &osvdev.Query{
			Commit: pkg.SourceCode.Commit,
		}
	}

	return nil
}

// withOptionalTimeoutCause creates a context that may time out after d.
// If d == 0, it just returns the original context.
func withOptionalTimeoutCause(ctx context.Context, d time.Duration, clause error) (context.Context, context.CancelFunc) {
	if d == 0 {
		return ctx, func() {}
	}
	return context.WithTimeoutCause(ctx, d, clause)
}
