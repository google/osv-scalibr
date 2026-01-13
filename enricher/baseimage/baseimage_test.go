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
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/mohae/deepcopy"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
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
			name: "valid_config",
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
	// Test layer metadata.
	// lm1: in base image alpine.
	// lm2: in base image nginx, but not an edge layer of the base image.
	// lm3: in base image nginx.
	lm1DiffID := digest.FromString("alpine")
	lm2DiffID := digest.FromString("nginxnonedge")
	lm3DiffID := digest.FromString("nginx")

	lm1ChainID := lm1DiffID.String()
	lm12ChainID := identity.ChainID([]digest.Digest{lm1DiffID, lm2DiffID}).String()
	lm123ChainID := identity.ChainID([]digest.Digest{lm1DiffID, lm2DiffID, lm3DiffID}).String()

	lm1 := &extractor.LayerMetadata{
		DiffID: lm1DiffID,
	}
	lm1Enriched := &extractor.LayerMetadata{
		DiffID:         lm1DiffID,
		BaseImageIndex: 2,
	}
	lm1EnrichedNoOtherBaseImages := &extractor.LayerMetadata{
		DiffID:         lm1DiffID,
		BaseImageIndex: 1,
	}
	lm2 := &extractor.LayerMetadata{
		DiffID: lm2DiffID,
	}
	lm2Enriched := &extractor.LayerMetadata{
		DiffID:         lm2DiffID,
		BaseImageIndex: 1,
	}
	lm3 := &extractor.LayerMetadata{
		DiffID: lm3DiffID,
	}
	lm3Enriched := &extractor.LayerMetadata{
		DiffID:         lm3DiffID,
		BaseImageIndex: 1,
	}
	clientErr := errors.New("client error")
	lmErrDiffID := digest.FromString("clienterror")
	lmErr := &extractor.LayerMetadata{
		DiffID: lmErrDiffID,
	}

	lm12ErrChainID := identity.ChainID([]digest.Digest{lm1DiffID, lm2DiffID, lmErrDiffID}).String()
	lmErr2ChainID := identity.ChainID([]digest.Digest{lmErrDiffID, lm2DiffID}).String()
	lmErr23ChainID := identity.ChainID([]digest.Digest{lmErrDiffID, lm2DiffID, lm3DiffID}).String()

	tests := []struct {
		name    string
		cfg     *baseimage.Config
		inv     *inventory.Inventory
		want    *inventory.Inventory
		wantErr error
	}{
		{
			name: "no_image_metadata_to_enrich",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{}),
			},
			inv:  &inventory.Inventory{},
			want: &inventory.Inventory{},
		},
		{
			name: "enrich_layers",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
					{
						req:  &baseimage.Request{ChainID: lm123ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"nginx"}}},
					},
					{
						req: &baseimage.Request{ChainID: lm12ChainID},
					},
					{
						req:  &baseimage.Request{ChainID: lm1ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"alpine"}}},
					},
				}}),
			},
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{LayerMetadata: []*extractor.LayerMetadata{lm1, lm2, lm3}},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1Enriched, lm2Enriched, lm3Enriched},
						BaseImages: [][]*extractor.BaseImageDetails{
							[]*extractor.BaseImageDetails{},
							[]*extractor.BaseImageDetails{
								&extractor.BaseImageDetails{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "baseimage",
								},
							},
							[]*extractor.BaseImageDetails{
								&extractor.BaseImageDetails{
									Repository: "alpine",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "baseimage",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "same_layer_chainID_in_different_images,_should_use_cache",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
					{
						req:  &baseimage.Request{ChainID: lm1ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"alpine"}}},
					},
				}}),
			},
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{LayerMetadata: []*extractor.LayerMetadata{lm1}},
					{LayerMetadata: []*extractor.LayerMetadata{lm1}},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1EnrichedNoOtherBaseImages},
						BaseImages: [][]*extractor.BaseImageDetails{
							[]*extractor.BaseImageDetails{},
							[]*extractor.BaseImageDetails{
								&extractor.BaseImageDetails{
									Repository: "alpine",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "baseimage",
								},
							},
						},
					},
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1EnrichedNoOtherBaseImages},
						BaseImages: [][]*extractor.BaseImageDetails{
							[]*extractor.BaseImageDetails{},
							[]*extractor.BaseImageDetails{
								&extractor.BaseImageDetails{
									Repository: "alpine",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "baseimage",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "client_error_on_last_layer",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
					{
						req: &baseimage.Request{ChainID: lm12ErrChainID},
						err: clientErr,
					},
					{
						req: &baseimage.Request{ChainID: lm12ChainID},
					},
					{
						req:  &baseimage.Request{ChainID: lm1ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"alpine"}}},
					},
				}}),
			},
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{LayerMetadata: []*extractor.LayerMetadata{lm1, lm2, lmErr}},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						// lm1 is enriched with the base image alpine.
						// lm2 is not enriched because the layer above it lmErr does not get enriched.
						// lmErr is not enriched because the client returns an error.
						LayerMetadata: []*extractor.LayerMetadata{lm1, lm2, lmErr},
						BaseImages: [][]*extractor.BaseImageDetails{
							[]*extractor.BaseImageDetails{},
						},
					},
				},
			},
			wantErr: clientErr,
		},
		{
			name: "client_error_on_first_layer",
			cfg: &baseimage.Config{
				Client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
					{
						req:  &baseimage.Request{ChainID: lmErr23ChainID},
						resp: &baseimage.Response{Results: []*baseimage.Result{&baseimage.Result{"nginx"}}},
					},
					{
						req: &baseimage.Request{ChainID: lmErr2ChainID},
					},
					{
						req: &baseimage.Request{ChainID: lmErrDiffID.String()},
						err: clientErr,
					},
				}}),
			},
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{LayerMetadata: []*extractor.LayerMetadata{lmErr, lm2, lm3}},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						// Nothing is enriched because one of the layer requests failed, everything is cancelled
						LayerMetadata: []*extractor.LayerMetadata{lmErr, lm2, lm3},
						BaseImages: [][]*extractor.BaseImageDetails{
							[]*extractor.BaseImageDetails{},
						},
					},
				},
			},
			wantErr: clientErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := mustNew(t, tc.cfg)
			inv := deepcopy.Copy(tc.inv).(*inventory.Inventory)
			if err := e.Enrich(t.Context(), nil, inv); !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("Enrich(%v) returned error: %v, want error: %v\n", tc.inv, err, tc.wantErr)
			}
			opts := []cmp.Option{
				protocmp.Transform(),
				cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer"),
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
