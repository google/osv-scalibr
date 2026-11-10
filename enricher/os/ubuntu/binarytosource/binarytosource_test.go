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

package binarytosource_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/os/ubuntu/binarytosource"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/chisel"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scalibr/plugin/config/configtest"
	osvapipb "osv.dev/bindings/go/api"
)

var errFake = errors.New("fake error")

// fakeClient returns canned binary-to-source mappings per ecosystem and
// records the requests it received.
type fakeClient struct {
	// Ecosystem -> binary name -> source names.
	mappings map[string]map[string][]string
	// Ecosystems for which the request fails.
	failing map[string]bool
	// Ecosystems for which the response has the wrong number of results.
	truncated map[string]bool

	mu       sync.Mutex
	requests []*osvapipb.UbuntuPackageMappingParameters
}

func (c *fakeClient) ExperimentalQueryUbuntuPackageMapping(_ context.Context, params *osvapipb.UbuntuPackageMappingParameters) (*osvapipb.UbuntuPackageMappingResponse, error) {
	c.mu.Lock()
	c.requests = append(c.requests, params)
	c.mu.Unlock()

	if c.failing[params.GetEcosystem()] {
		return nil, errFake
	}
	resp := &osvapipb.UbuntuPackageMappingResponse{}
	for _, name := range params.GetBinaryNames() {
		resp.Results = append(resp.Results, &osvapipb.SourcePackages{
			SourceNames: c.mappings[params.GetEcosystem()][name],
		})
	}
	if c.truncated[params.GetEcosystem()] {
		resp.Results = resp.Results[:len(resp.Results)-1]
	}
	return resp, nil
}

type pkgOpts struct {
	plugin     string
	osID       string
	versionID  string
	sourceName string
}

func newPkg(name string, opts pkgOpts) *extractor.Package {
	if opts.plugin == "" {
		opts.plugin = chisel.Name
	}
	if opts.osID == "" {
		opts.osID = "ubuntu"
	}
	return &extractor.Package{
		Name:     name,
		Version:  "1.0-1",
		PURLType: purl.TypeDebian,
		Metadata: &dpkgmeta.Metadata{
			PackageName:    name,
			PackageVersion: "1.0-1",
			SourceName:     opts.sourceName,
			OSID:           opts.osID,
			OSVersionID:    opts.versionID,
		},
		Plugins: []string{opts.plugin},
	}
}

func sourceNames(inv *inventory.Inventory) map[string][]string {
	got := map[string][]string{}
	for _, pkg := range inv.Packages {
		m := pkg.Metadata.(*dpkgmeta.Metadata)
		key := m.OSVersionID + "/" + pkg.Name
		got[key] = append(got[key], m.SourceName)
	}
	return got
}

func TestEnrich(t *testing.T) {
	noble := pkgOpts{versionID: "24.04"}
	jammy := pkgOpts{versionID: "22.04"}

	cancelledCtx, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name string
		//nolint:containedctx
		ctx          context.Context
		timeout      time.Duration
		packages     []*extractor.Package
		client       *fakeClient
		wantSources  map[string][]string
		wantRequests []*osvapipb.UbuntuPackageMappingParameters
		wantErr      error
	}{
		{
			name: "single_source_name_is_set",
			packages: []*extractor.Package{
				newPkg("libcurl4t64", noble),
			},
			client: &fakeClient{mappings: map[string]map[string][]string{
				"Ubuntu:24.04": {"libcurl4t64": {"curl"}},
			}},
			wantSources: map[string][]string{"24.04/libcurl4t64": {"curl"}},
			wantRequests: []*osvapipb.UbuntuPackageMappingParameters{
				{Ecosystem: "Ubuntu:24.04", BinaryNames: []string{"libcurl4t64"}},
			},
		},
		{
			name: "zero_source_names_leaves_package_unchanged_and_multiple_creates_entries",
			packages: []*extractor.Package{
				newPkg("unknown", noble),
				newPkg("multi-src", noble),
			},
			client: &fakeClient{mappings: map[string]map[string][]string{
				"Ubuntu:24.04": {"multi-src": {"src1", "src2"}},
			}},
			wantSources: map[string][]string{
				"24.04/unknown":   {""},
				"24.04/multi-src": {"src1", "src2"},
			},
			wantRequests: []*osvapipb.UbuntuPackageMappingParameters{
				{Ecosystem: "Ubuntu:24.04", BinaryNames: []string{"multi-src", "unknown"}},
			},
		},
		{
			name: "non_chisel_non_ubuntu_and_already_mapped_packages_are_skipped",
			packages: []*extractor.Package{
				newPkg("dpkg-pkg", pkgOpts{plugin: dpkg.Name, versionID: "24.04"}),
				newPkg("debian-pkg", pkgOpts{osID: "debian", versionID: "12"}),
				newPkg("libssl3t64", pkgOpts{versionID: "24.04", sourceName: "openssl"}),
			},
			client: &fakeClient{mappings: map[string]map[string][]string{
				"Ubuntu:24.04": {"dpkg-pkg": {"x"}, "libssl3t64": {"x"}},
			}},
			wantSources: map[string][]string{
				"24.04/dpkg-pkg":   {""},
				"12/debian-pkg":    {""},
				"24.04/libssl3t64": {"openssl"},
			},
		},
		{
			name: "packages_without_release_are_skipped",
			packages: []*extractor.Package{
				newPkg("libc6", pkgOpts{}),
			},
			client:      &fakeClient{},
			wantSources: map[string][]string{"/libc6": {""}},
		},
		{
			name: "one_request_per_ecosystem_with_deduplicated_names",
			packages: []*extractor.Package{
				newPkg("libc6", noble),
				newPkg("libc6", noble),
				newPkg("libc6", jammy),
				newPkg("libssl3", jammy),
			},
			client: &fakeClient{mappings: map[string]map[string][]string{
				"Ubuntu:24.04": {"libc6": {"glibc"}},
				"Ubuntu:22.04": {"libc6": {"glibc"}, "libssl3": {"openssl"}},
			}},
			wantSources: map[string][]string{
				"24.04/libc6":   {"glibc", "glibc"},
				"22.04/libc6":   {"glibc"},
				"22.04/libssl3": {"openssl"},
			},
			wantRequests: []*osvapipb.UbuntuPackageMappingParameters{
				{Ecosystem: "Ubuntu:22.04", BinaryNames: []string{"libc6", "libssl3"}},
				{Ecosystem: "Ubuntu:24.04", BinaryNames: []string{"libc6"}},
			},
		},
		{
			name: "failed_ecosystem_does_not_block_others",
			packages: []*extractor.Package{
				newPkg("libc6", noble),
				newPkg("libssl3", jammy),
			},
			client: &fakeClient{
				mappings: map[string]map[string][]string{
					"Ubuntu:24.04": {"libc6": {"glibc"}},
				},
				failing: map[string]bool{"Ubuntu:22.04": true},
			},
			wantSources: map[string][]string{
				"24.04/libc6":   {"glibc"},
				"22.04/libssl3": {""},
			},
			wantRequests: []*osvapipb.UbuntuPackageMappingParameters{
				{Ecosystem: "Ubuntu:22.04", BinaryNames: []string{"libssl3"}},
				{Ecosystem: "Ubuntu:24.04", BinaryNames: []string{"libc6"}},
			},
			wantErr: errFake,
		},
		{
			name: "mismatched_result_count_is_an_error",
			packages: []*extractor.Package{
				newPkg("libc6", noble),
				newPkg("libssl3t64", noble),
			},
			client: &fakeClient{
				mappings: map[string]map[string][]string{
					"Ubuntu:24.04": {"libc6": {"glibc"}, "libssl3t64": {"openssl"}},
				},
				truncated: map[string]bool{"Ubuntu:24.04": true},
			},
			wantSources: map[string][]string{
				"24.04/libc6":      {""},
				"24.04/libssl3t64": {""},
			},
			wantRequests: []*osvapipb.UbuntuPackageMappingParameters{
				{Ecosystem: "Ubuntu:24.04", BinaryNames: []string{"libc6", "libssl3t64"}},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			name: "ctx_cancelled",
			ctx:  cancelledCtx,
			packages: []*extractor.Package{
				newPkg("libc6", noble),
			},
			client:      &fakeClient{},
			wantSources: map[string][]string{"24.04/libc6": {""}},
			wantErr:     context.Canceled,
		},
		{
			name:    "query_timeout",
			timeout: -1 * time.Second,
			packages: []*extractor.Package{
				newPkg("libc6", noble),
			},
			client:      &fakeClient{},
			wantSources: map[string][]string{"24.04/libc6": {""}},
			wantErr:     binarytosource.ErrQueryTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			e := binarytosource.NewWithClient(tc.client, tc.timeout)
			inv := &inventory.Inventory{Packages: tc.packages}

			err := e.Enrich(ctx, &enricher.ScanInput{}, inv)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Enrich() error mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantSources, sourceNames(inv)); diff != "" {
				t.Errorf("Enrich() source names mismatch (-want +got):\n%s", diff)
			}
			sortRequests := cmpopts.SortSlices(func(a, b *osvapipb.UbuntuPackageMappingParameters) bool {
				return a.GetEcosystem() < b.GetEcosystem()
			})
			if diff := cmp.Diff(tc.wantRequests, tc.client.requests, protocmp.Transform(), sortRequests, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Enrich() requests mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEnrich_SourceNameUsedInPURL(t *testing.T) {
	pkg := newPkg("libcurl4t64", pkgOpts{versionID: "24.04"})
	client := &fakeClient{mappings: map[string]map[string][]string{
		"Ubuntu:24.04": {"libcurl4t64": {"curl"}},
	}}
	inv := &inventory.Inventory{Packages: []*extractor.Package{pkg}}

	if err := binarytosource.NewWithClient(client, 0).Enrich(t.Context(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich() returned an error: %v", err)
	}

	got := pkg.PURL().String()
	if !strings.Contains(got, purl.Source+"=curl") {
		t.Errorf("PURL %q does not contain %s=curl", got, purl.Source)
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.PluginConfig
		wantErr bool
	}{
		{
			name:    "nil_plugin_config",
			cfg:     nil,
			wantErr: true,
		},
		{
			name:    "nil_client_factories",
			cfg:     &config.PluginConfig{},
			wantErr: true,
		},
		{
			name: "nil_http_client",
			cfg: &config.PluginConfig{
				ClientFactories: &configtest.FakeClientFactories{},
			},
			wantErr: true,
		},
		{
			name: "default_config",
			cfg:  configtest.NewFakePluginConfig(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := binarytosource.New(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && e.Name() != binarytosource.Name {
				t.Errorf("New().Name() = %q, want %q", e.Name(), binarytosource.Name)
			}
		})
	}
}

func TestNew_CustomBaseURLAndUserAgent(t *testing.T) {
	var gotPath, gotUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUA = r.Header.Get("User-Agent")
		out, err := protojson.Marshal(&osvapipb.UbuntuPackageMappingResponse{
			Results: []*osvapipb.SourcePackages{{SourceNames: []string{"curl"}}},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}))
	defer server.Close()

	cf := config.NewDefaultClientFactories("custom-user-agent/1.0")
	defer cf.Close()

	e, err := binarytosource.New(&config.PluginConfig{
		ClientFactories: cf,
		ProtoConfig: &cpb.PluginConfig{
			PluginSpecific: []*cpb.PluginSpecificConfig{
				{Config: &cpb.PluginSpecificConfig_UbuntuBinaryToSource{
					UbuntuBinaryToSource: &cpb.UbuntuBinaryToSourceConfig{
						BaseUrl:        server.URL + "/",
						TimeoutSeconds: 10,
					},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("New() returned an error: %v", err)
	}

	pkg := newPkg("libcurl4t64", pkgOpts{versionID: "24.04"})
	inv := &inventory.Inventory{Packages: []*extractor.Package{pkg}}
	if err := e.Enrich(t.Context(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich() returned an error: %v", err)
	}

	if wantPath := "/v1experimental/ubuntu/binary-to-source"; gotPath != wantPath {
		t.Errorf("request path = %q, want %q", gotPath, wantPath)
	}
	if wantUA := "custom-user-agent/1.0"; gotUA != wantUA {
		t.Errorf("request User-Agent = %q, want %q", gotUA, wantUA)
	}
	if got := pkg.Metadata.(*dpkgmeta.Metadata).SourceName; got != "curl" {
		t.Errorf("SourceName = %q, want %q", got, "curl")
	}
}
