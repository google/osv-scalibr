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

package baseimage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/mohae/deepcopy"
	"github.com/opencontainers/go-digest"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *baseimage.Config
		wantErr error
	}{
		{
			name:    "nil config",
			wantErr: cmpopts.AnyError,
		},
		{
			name:    "nil client",
			cfg:     &baseimage.Config{},
			wantErr: cmpopts.AnyError,
		},
		{
			name: "valid config",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{}),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := baseimage.New(tc.cfg)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("New(%v) returned an unexpected error: %v", tc.cfg, err)
			}
			if err != nil && got == nil {
				return
			}
			opts := []cmp.Option{
				cmp.AllowUnexported(clientFake{}),
			}
			if diff := cmp.Diff(tc.cfg, got.Config(), opts...); diff != "" {
				t.Errorf("New(%v) returned an unexpected diff (-want +got): %v", tc.cfg, diff)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	e := baseimage.Enricher{}
	if e.Version() != baseimage.Version {
		t.Errorf("Version() = %q, want %q", e.Version(), baseimage.Version)
	}
}

func TestRequirements(t *testing.T) {
	e := &baseimage.Enricher{}
	got := e.Requirements()
	want := &plugin.Capabilities{Network: plugin.NetworkOnline}
	opts := []cmp.Option{
		protocmp.Transform(),
	}
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("Requirements() returned diff (-want +got):\n%s", diff)
	}
}

func TestRequiredPlugins(t *testing.T) {
	e := &baseimage.Enricher{}
	got := e.RequiredPlugins()
	want := []string{}
	opts := []cmp.Option{
		protocmp.Transform(),
	}
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("RequiredPlugins() returned diff (-want +got):\n%s", diff)
	}
}

func TestEnrich(t *testing.T) {
	// Test packages.
	pkg1 := &extractor.Package{
		Name:    "curl1",
		Version: "1.2.3",
	}
	pkg2 := &extractor.Package{
		Name:    "curl2",
		Version: "2.3.4",
	}
	pkg3 := &extractor.Package{
		Name:    "curl3",
		Version: "3.4.5",
	}

	// Test layer details.
	// ld1: in base image alpine.
	// ld2: not in base image.
	// ld3: in base image debian.
	ld1 := &extractor.LayerDetails{
		ChainID: "sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
	}
	ld1base := &extractor.LayerDetails{
		ChainID:     "sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
		InBaseImage: true,
	}
	ld2 := &extractor.LayerDetails{
		ChainID: "sha256:d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
	}
	ld3 := &extractor.LayerDetails{
		ChainID: "sha256:4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
	}
	ld3base := &extractor.LayerDetails{
		ChainID:     "sha256:4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
		InBaseImage: true,
	}
	ldWrong := &extractor.LayerDetails{
		ChainID: "sha123:abcd",
	}
	clientErr := errors.New("client error")
	ldErr := &extractor.LayerDetails{
		ChainID: "sha256:53e60bc18399d11a8953c224619cd6147f2f8ef1233acf2818575ba1a17f7ca2",
	}
	withLayerDetails := func(pkg *extractor.Package, ld *extractor.LayerDetails) *extractor.Package {
		pkg = deepcopy.Copy(pkg).(*extractor.Package)
		pkg.LayerDetails = ld
		return pkg
	}

	// Additional scan result types to ensure they are not modified.
	finding1 := &detector.Finding{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-2024-1234",
			},
		},
	}
	finding2 := &detector.Finding{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-2024-5678",
			},
		},
	}

	tests := []struct {
		name    string
		cfg     *baseimage.Config
		inv     *inventory.Inventory
		want    *inventory.Inventory
		wantErr error
	}{
		{
			name: "no packages to enrich",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{}),
			},
			inv:  &inventory.Inventory{},
			want: &inventory.Inventory{},
		},
		{
			name: "packages with no layer details",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{}),
			},
			inv:  &inventory.Inventory{Packages: []*extractor.Package{pkg1, pkg2, pkg3}},
			want: &inventory.Inventory{Packages: []*extractor.Package{pkg1, pkg2, pkg3}},
		},
		{
			name: "packages with layer details",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
					{
						req:  &baseimage.Request{ChainID: ld1.ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"alpine"}}},
					},
					{
						req: &baseimage.Request{ChainID: ld2.ChainID},
					},
					{
						req:  &baseimage.Request{ChainID: ld3.ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"debian"}}},
					},
				}}),
			},
			inv: &inventory.Inventory{Packages: []*extractor.Package{
				withLayerDetails(pkg1, ld1),
				withLayerDetails(pkg2, ld2),
				withLayerDetails(pkg3, ld3),
			}},
			want: &inventory.Inventory{Packages: []*extractor.Package{
				withLayerDetails(pkg1, ld1base),
				withLayerDetails(pkg2, ld2),
				withLayerDetails(pkg3, ld3base),
			}},
		},
		{
			name: "packages with layer details and other inventory",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
					{
						req:  &baseimage.Request{ChainID: ld1.ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"alpine"}}},
					},
					{
						req: &baseimage.Request{ChainID: ld2.ChainID},
					},
					{
						req:  &baseimage.Request{ChainID: ld3.ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"debian"}}},
					},
				}}),
			},
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					withLayerDetails(pkg1, ld1),
					withLayerDetails(pkg2, ld2),
					withLayerDetails(pkg3, ld3),
				},
				Findings: []*detector.Finding{finding1, finding2},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					withLayerDetails(pkg1, ld1base),
					withLayerDetails(pkg2, ld2),
					withLayerDetails(pkg3, ld3base),
				},
				Findings: []*detector.Finding{finding1, finding2},
			},
		},
		{
			name: "packages with some invalid layer details",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
					{
						req:  &baseimage.Request{ChainID: ld1.ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"alpine"}}},
					},
					// No call for ld2 because it's malformed.
					{
						req:  &baseimage.Request{ChainID: ld3.ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"debian"}}},
					},
				}}),
			},
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					withLayerDetails(pkg1, ld1),
					withLayerDetails(pkg2, ldWrong),
					withLayerDetails(pkg3, ld3),
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					withLayerDetails(pkg1, ld1base),
					withLayerDetails(pkg2, ldWrong),
					withLayerDetails(pkg3, ld3base),
				},
			},
			wantErr: digest.ErrDigestUnsupported,
		},
		{
			name: "packages with layer details, and client error",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
					{
						req:  &baseimage.Request{ChainID: ld1.ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"alpine"}}},
					},
					{
						req: &baseimage.Request{ChainID: ld2.ChainID},
					},
					{
						req: &baseimage.Request{ChainID: ldErr.ChainID},
						err: clientErr,
					},
				}}),
			},
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					withLayerDetails(pkg1, ld1),
					withLayerDetails(pkg2, ld2),
					withLayerDetails(pkg3, ldErr),
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					withLayerDetails(pkg1, ld1base),
					withLayerDetails(pkg2, ld2),
					withLayerDetails(pkg3, ldErr),
				},
			},
			wantErr: clientErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := mustNew(t, tc.cfg)
			inv := deepcopy.Copy(tc.inv).(*inventory.Inventory)
			if err := e.Enrich(context.Background(), nil, inv); !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("Enrich(%v) returned error: %v, want error: %v\n", tc.inv, err, tc.wantErr)
			}
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, inv, opts...); diff != "" {
				t.Errorf("Enrich(%v) returned diff (-want +got):\n%s\n", tc.inv, diff)
			}
		})
	}
}

func mustNew(t *testing.T, cfg *baseimage.Config) *baseimage.Enricher {
	t.Helper()
	e, err := baseimage.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create base image enricher: %v", err)
	}
	return e
}
