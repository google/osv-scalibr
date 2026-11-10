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

// Package binarytosource provides an Enricher that fills in the source package
// name of Ubuntu packages that were extracted without one (e.g. from chisel
// manifests) by querying the OSV.dev Ubuntu binary-to-source mapping API.
//
// Ubuntu vulnerability advisories in OSV are indexed by source package name, so
// this Enricher needs to run before the vulnerability matching Enrichers.
package binarytosource

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/chisel"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"osv.dev/bindings/go/osvdev"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/plugin/config"
	osvapipb "osv.dev/bindings/go/api"
)

const (
	// Name is the unique name of this Enricher.
	Name = "os/ubuntu/binarytosource"

	version        = 0
	defaultBaseURL = osvdev.DefaultBaseURL
	defaultTimeout = 5 * time.Minute
)

// ErrQueryTimeout is returned if the query to OSV.dev times out.
var ErrQueryTimeout = errors.New("query timeout reached")

var _ enricher.Enricher = &Enricher{}

// Client is the subset of the OSV.dev client used by this Enricher.
type Client interface {
	ExperimentalQueryUbuntuPackageMapping(ctx context.Context, params *osvapipb.UbuntuPackageMappingParameters) (*osvapipb.UbuntuPackageMappingResponse, error)
}

// Enricher fills in the source package names of Ubuntu packages using the
// OSV.dev Ubuntu binary-to-source mapping API.
type Enricher struct {
	client  Client
	timeout time.Duration
}

// New creates a new Enricher with the given configuration.
func New(cfg *config.PluginConfig) (enricher.Enricher, error) {
	if cfg == nil || cfg.ClientFactories == nil {
		return nil, fmt.Errorf("client factories not configured for %s", Name)
	}
	httpClient := cfg.ClientFactories.HTTPClient()
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client is nil for %s", Name)
	}

	baseURL := defaultBaseURL
	timeout := defaultTimeout
	specific := plugin.FindConfig(cfg.ProtoConfig, func(c *cpb.PluginSpecificConfig) *cpb.UbuntuBinaryToSourceConfig {
		return c.GetUbuntuBinaryToSource()
	})
	if specific.GetBaseUrl() != "" {
		baseURL = strings.TrimRight(specific.GetBaseUrl(), "/")
	}
	if specific.GetTimeoutSeconds() > 0 {
		timeout = time.Duration(specific.GetTimeoutSeconds()) * time.Second
	}

	client := osvdev.DefaultClient()
	client.HTTPClient = httpClient
	client.BaseHostURL = baseURL
	client.Config.UserAgent = ""

	return &Enricher{
		client:  client,
		timeout: timeout,
	}, nil
}

// NewWithClient returns an Enricher which uses the specified client and timeout.
func NewWithClient(c Client, timeout time.Duration) enricher.Enricher {
	return &Enricher{
		client:  c,
		timeout: timeout,
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
// Needs network access so it can query the OSV.dev API.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// RequiredPlugins returns the plugins that are required to be enabled for this
// Enricher to run. While it works on the results of the chisel Extractor, the
// Enricher itself can run independently.
func (Enricher) RequiredPlugins() []string {
	return []string{}
}

// Enrich sets the source package name of Ubuntu chisel packages that don't
// have one, based on the OSV.dev Ubuntu binary-to-source mapping.
//
// Packages are left unchanged if the API returns no source package names for
// them, or if the request for their ecosystem fails. If multiple source package
// names are returned for a binary package, additional package entries are
// added to the inventory for each extra source package.
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	// Ecosystem -> binary package name -> packages to update.
	toEnrich := make(map[string]map[string][]*extractor.Package)
	for _, pkg := range inv.Packages {
		if !slices.Contains(pkg.Plugins, chisel.Name) {
			continue
		}
		m, ok := pkg.Metadata.(*dpkgmeta.Metadata)
		if !ok || m.OSID != "ubuntu" || m.SourceName != "" || pkg.Name == "" {
			continue
		}
		eco := pkg.Ecosystem()
		// The API requires an Ubuntu release, e.g. "Ubuntu:24.04".
		if eco.Ecosystem != osvconstants.EcosystemUbuntu || eco.Suffix == "" {
			continue
		}
		ecosystem := eco.String()
		if toEnrich[ecosystem] == nil {
			toEnrich[ecosystem] = make(map[string][]*extractor.Package)
		}
		toEnrich[ecosystem][pkg.Name] = append(toEnrich[ecosystem][pkg.Name], pkg)
	}

	if len(toEnrich) == 0 {
		return nil
	}

	queryCtx := ctx
	if e.timeout != 0 {
		var cancel context.CancelFunc
		queryCtx, cancel = context.WithTimeoutCause(ctx, e.timeout, ErrQueryTimeout)
		defer cancel()
	}

	var errs []error
	for _, ecosystem := range slices.Sorted(maps.Keys(toEnrich)) {
		if queryCtx.Err() != nil {
			break
		}
		if err := e.enrichEcosystem(queryCtx, ecosystem, toEnrich[ecosystem], inv); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(append(errs, context.Cause(queryCtx))...)
}

func (e *Enricher) enrichEcosystem(ctx context.Context, ecosystem string, binaryToPackages map[string][]*extractor.Package, inv *inventory.Inventory) error {
	binaryNames := slices.Sorted(maps.Keys(binaryToPackages))
	resp, err := e.client.ExperimentalQueryUbuntuPackageMapping(ctx, &osvapipb.UbuntuPackageMappingParameters{
		Ecosystem:   ecosystem,
		BinaryNames: binaryNames,
	})
	if err != nil {
		return fmt.Errorf("%s: querying binary-to-source mapping for %q: %w", Name, ecosystem, err)
	}

	results := resp.GetResults()
	if len(results) != len(binaryNames) {
		return fmt.Errorf("%s: binary-to-source mapping for %q returned %d results, want %d", Name, ecosystem, len(results), len(binaryNames))
	}

	for i, binaryName := range binaryNames {
		sourceNames := results[i].GetSourceNames()
		if len(sourceNames) == 0 {
			continue
		}
		for _, pkg := range binaryToPackages[binaryName] {
			pkg.Metadata.(*dpkgmeta.Metadata).SourceName = sourceNames[0]
			for _, sourceName := range sourceNames[1:] {
				clonedMeta := *pkg.Metadata.(*dpkgmeta.Metadata)
				clonedMeta.SourceName = sourceName
				clonedPkg := *pkg
				clonedPkg.ID = ""
				clonedPkg.Metadata = &clonedMeta
				inv.Packages = append(inv.Packages, &clonedPkg)
			}
		}
	}

	return nil
}
