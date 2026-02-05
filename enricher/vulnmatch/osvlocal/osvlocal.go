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

// Package osvlocal uses the osv.dev export bucket to find vulnerabilities in inventory packages
package osvlocal

import (
	"context"
	"maps"
	"slices"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	scalibrversion "github.com/google/osv-scalibr/version"
)

const (
	// Name is the unique name of this Enricher.
	Name    = "vulnmatch/osvlocal"
	version = 1
)

var _ enricher.Enricher = &Enricher{}

// Enricher uses the OSV.dev zip databases to find vulnerabilities in the inventory packages
type Enricher struct {
	zippedDBRemoteHost string

	userAgent string
	localPath string
	download  bool
}

// New makes a new osvlocal.Enricher with the given config.
func New(cfg *cpb.PluginConfig) (enricher.Enricher, error) {
	userAgent := "osv-scanner_scan/" + scalibrversion.ScannerVersion
	remoteHost := "https://osv-vulnerabilities.storage.googleapis.com"
	localPath := ""
	download := true

	if cfg.UserAgent != "" {
		userAgent = cfg.UserAgent
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.OSVLocalConfig { return c.GetOsvlocal() })
	if specific != nil {
		remoteHost = specific.RemoteHost
		localPath = specific.LocalPath
		download = specific.Download
	}

	return &Enricher{
		zippedDBRemoteHost: remoteHost,

		userAgent: userAgent,
		localPath: localPath,
		download:  download,
	}, nil
}

func newForTesting(zippedDBRemoteHost string) enricher.Enricher {
	return &Enricher{zippedDBRemoteHost, "", "", true}
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
// Needs network access if database downloading is enabled.
func (e Enricher) Requirements() *plugin.Capabilities {
	network := plugin.NetworkOffline

	if e.download {
		network = plugin.NetworkOnline
	}

	return &plugin.Capabilities{
		Network: network,
	}
}

// RequiredPlugins returns the plugins that are required to be enabled for this
// Enricher to run. While it works on the results of other extractors,
// the Enricher itself can run independently.
func (Enricher) RequiredPlugins() []string {
	return []string{}
}

// Enrich checks for vulnerabilities in the inventory packages using zip files exported by osv.dev
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	dbs, err := newlocalMatcher(
		e.localPath,
		e.userAgent,
		e.download,
		e.zippedDBRemoteHost,
	)

	if err != nil {
		return err
	}

	for _, pkg := range inv.Packages {
		vulns, err := dbs.MatchVulnerabilities(ctx, pkg, inv.Packages)

		if err != nil {
			return err
		}

		for _, vuln := range vulns {
			inv.PackageVulns = append(inv.PackageVulns, &inventory.PackageVuln{
				Vulnerability:         vuln,
				Package:               pkg,
				ExploitabilitySignals: vex.FindingVEXFromPackageVEX(vuln.Id, pkg.ExploitabilitySignals),
				Plugins:               []string{Name},
			})
		}
	}

	// It's possible for other enrichers/detectors to have already added the same vulnerability
	// for the same package, so we deduplicate and merge the results.
	inv.PackageVulns = dedupPackageVulns(inv.PackageVulns)

	return nil
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
		k := key{vv.Package, vv.Vulnerability.Id}
		if v, ok := dedupVulns[k]; !ok {
			dedupVulns[k] = vv
		} else {
			// use the latest (from OSV.dev) as source of truth
			vv.Plugins = append(v.Plugins, vv.Plugins...)
			dedupVulns[k] = vv
		}
	}

	return slices.Collect(maps.Values(dedupVulns))
}
