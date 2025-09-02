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
	scalibrversion "github.com/google/osv-scalibr/version"
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

// ErrInitialQueryTimeout is returned if the initial query to OSV.dev partially fails due to timeout
var ErrInitialQueryTimeout = errors.New("initialQueryTimeout reached")

var _ enricher.Enricher = &Enricher{}

// Enricher queries the OSV.dev API to find vulnerabilities in the inventory packages
type Enricher struct {
	client              Client
	initialQueryTimeout time.Duration
}

// NewWithClient returns an Enricher which uses a specified deps.dev client.
func NewWithClient(c Client, initialQueryTimeout time.Duration) enricher.Enricher {
	return &Enricher{
		client:              c,
		initialQueryTimeout: initialQueryTimeout,
	}
}

// NewDefault creates a new Enricher with the default configuration and OSV.dev client
func NewDefault() enricher.Enricher {
	client := osvdev.DefaultClient()
	client.Config.UserAgent = "osv-scanner_scan/" + scalibrversion.ScannerVersion
	return &Enricher{
		initialQueryTimeout: 5 * time.Minute,
		client:              client,
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
	pkgs := make([]*extractor.Package, 0, len(inv.Packages))
	queries := make([]*osvdev.Query, 0, len(inv.Packages))
	for _, pkg := range inv.Packages {
		if query := pkgToQuery(pkg); query != nil {
			pkgs = append(pkgs, pkg)
			queries = append(queries, query)
		}
	}

	if len(queries) == 0 {
		return nil
	}

	queryCtx, cancel := withOptionalTimeoutCause(ctx, e.initialQueryTimeout, ErrInitialQueryTimeout)
	defer cancel()

	batchResp, initialQueryErr := osvdevexperimental.BatchQueryPaging(queryCtx, e.client, queries)
	initialQueryErr = errors.Join(initialQueryErr, context.Cause(queryCtx))

	// if an error happened and is not caused by the initialQueryTimeout return it
	if initialQueryErr != nil && !errors.Is(initialQueryErr, ErrInitialQueryTimeout) {
		return initialQueryErr
	}

	// if batchResp is not usable return the initial error anyway
	if batchResp == nil {
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
			inv.PackageVulns = append(inv.PackageVulns, &inventory.PackageVuln{
				Vulnerability:         *vuln,
				Package:               pkg,
				ExploitabilitySignals: vex.FindingVEXFromPackageVEX(vuln.ID, pkg.ExploitabilitySignals),
				Plugins:               []string{Name},
			})
		}
	}

	// It's possible for other enrichers/detectors to have already added the same vulnerability
	// for the same package, so we deduplicate and merge the results.
	inv.PackageVulns = dedupPackageVulns(inv.PackageVulns)

	// return to the caller the initialQueryErr, which if not nil indicates that
	// the list of vulnerabilities is not complete
	return initialQueryErr
}

// dedupPackageVulns deduplicate package vulnerabilities that have the same pkg and vulnID
func dedupPackageVulns(vulns []*inventory.PackageVuln) []*inventory.PackageVuln {
	if len(vulns) == 0 {
		return vulns
	}

	type key struct {
		pkg    *extractor.Package
		vulnID string
	}
	dedupVulns := map[key]*inventory.PackageVuln{}

	for _, vv := range vulns {
		if vuln, ok := dedupVulns[key{vv.Package, vv.ID}]; !ok {
			dedupVulns[key{vv.Package, vv.ID}] = vv
		} else {
			// use the latest (from OSV.dev) as source of truth
			dedupVulns[key{vv.Package, vv.ID}] = vv
			dedupVulns[key{vv.Package, vv.ID}].Plugins = append(dedupVulns[key{vv.Package, vv.ID}].Plugins, vuln.Plugins...)
		}
	}

	return slices.Collect(maps.Values(dedupVulns))
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
	if pkg.Name != "" && !pkg.Ecosystem().IsEmpty() && pkg.Version != "" {
		// TODO(#1222): Ecosystems could return ecosystems
		return &osvdev.Query{
			Package: osvdev.Package{
				Name:      pkg.Name,
				Ecosystem: pkg.Ecosystem().String(),
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
