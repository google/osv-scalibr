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

	"github.com/google/osv-scalibr/plugin/config/configtest"
)

func TestVersion(t *testing.T) {
	e := baseimage.Enricher{}
	if e.Version() != baseimage.Version {
		t.Errorf("Version() = %d, want %d", e.Version(), baseimage.Version)
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
		client  baseimage.Client
		inv     *inventory.Inventory
		want    *inventory.Inventory
		wantErr error
	}{
		{
			name:   "no_image_metadata_to_enrich",
			client: mustNewClientFake(t, &config{}),
			inv:    &inventory.Inventory{},
			want:   &inventory.Inventory{},
		},
		{
			name: "enrich_layers",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req:  &baseimage.Request{ChainID: lm123ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"nginx"}}},
				},
				{
					req: &baseimage.Request{ChainID: lm12ChainID},
				},
				{
					req:  &baseimage.Request{ChainID: lm1ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"alpine"}}},
				},
			}}),
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
							{},
							{
								{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "baseimage",
								},
							},
							{
								{
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
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req:  &baseimage.Request{ChainID: lm1ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"alpine"}}},
				},
			}}),
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
							{},
							{
								{
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
							{},
							{
								{
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
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req: &baseimage.Request{ChainID: lm12ErrChainID},
					err: clientErr,
				},
				{
					req: &baseimage.Request{ChainID: lm12ChainID},
				},
				{
					req:  &baseimage.Request{ChainID: lm1ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"alpine"}}},
				},
			}}),
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
							{},
						},
					},
				},
			},
			wantErr: clientErr,
		},
		{
			name: "client_error_on_first_layer",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req:  &baseimage.Request{ChainID: lmErr23ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"nginx"}}},
				},
				{
					req: &baseimage.Request{ChainID: lmErr2ChainID},
				},
				{
					req: &baseimage.Request{ChainID: lmErrDiffID.String()},
					err: clientErr,
				},
			}}),
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
							{},
						},
					},
				},
			},
			wantErr: clientErr,
		},
		{
			name: "existing_base_images_same_boundary_merged",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req: &baseimage.Request{ChainID: lm123ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{
						{"nginx"},
						{"nginx-mirror"},
					}},
				},
				{
					req: &baseimage.Request{ChainID: lm12ChainID},
				},
				{
					req:  &baseimage.Request{ChainID: lm1ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"alpine"}}},
				},
			}}),
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
							{DiffID: lm2DiffID, BaseImageIndex: 1},
							{DiffID: lm3DiffID, BaseImageIndex: 1},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "other",
								},
								{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1Enriched, lm2Enriched, lm3Enriched},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "other",
								},
								{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "other",
								},
								{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "baseimage",
								},
								{
									Repository: "nginx-mirror",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "baseimage",
								},
							},
							{
								{
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
			name: "existing_base_images_on_inner_layer_and_depsdev_on_outer_layer",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req:  &baseimage.Request{ChainID: lm123ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"nginx"}}},
				},
				{
					req: &baseimage.Request{ChainID: lm12ChainID},
				},
				{
					req: &baseimage.Request{ChainID: lm1ChainID},
				},
			}}),
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
							{DiffID: lm2DiffID, BaseImageIndex: 0},
							{DiffID: lm3DiffID, BaseImageIndex: 0},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-alpine",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1Enriched, lm2Enriched, lm3Enriched},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "baseimage",
								},
							},
							{
								{
									Repository: "custom-alpine",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "existing_base_images_preserved_when_depsdev_returns_no_results",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req: &baseimage.Request{ChainID: lm123ChainID},
				},
				{
					req: &baseimage.Request{ChainID: lm12ChainID},
				},
				{
					req: &baseimage.Request{ChainID: lm1ChainID},
				},
			}}),
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
							{DiffID: lm2DiffID, BaseImageIndex: 1},
							{DiffID: lm3DiffID, BaseImageIndex: 0},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm12ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
							{DiffID: lm2DiffID, BaseImageIndex: 1},
							{DiffID: lm3DiffID, BaseImageIndex: 0},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm12ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "existing_base_images_preserved_on_client_error",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req: &baseimage.Request{ChainID: lm12ErrChainID},
					err: clientErr,
				},
				{
					req: &baseimage.Request{ChainID: lm12ChainID},
				},
				{
					req:  &baseimage.Request{ChainID: lm1ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"alpine"}}},
				},
			}}),
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
							{DiffID: lm2DiffID, BaseImageIndex: 0},
							{DiffID: lmErrDiffID, BaseImageIndex: 0},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-alpine",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
							{DiffID: lm2DiffID, BaseImageIndex: 0},
							{DiffID: lmErrDiffID, BaseImageIndex: 0},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-alpine",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
			wantErr: clientErr,
		},
		{
			name: "cache_does_not_leak_existing_base_images_across_images",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req:  &baseimage.Request{ChainID: lm1ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"alpine"}}},
				},
			}}),
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-alpine",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "other",
								},
							},
						},
					},
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1},
					},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1EnrichedNoOtherBaseImages},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-alpine",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "other",
								},
								{
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
							{},
							{
								{
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
			name: "multiple_existing_base_image_runs_merged_with_depsdev",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req:  &baseimage.Request{ChainID: lm123ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"nginx"}}},
				},
				{
					req: &baseimage.Request{ChainID: lm12ChainID},
				},
				{
					req:  &baseimage.Request{ChainID: lm1ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"alpine"}}},
				},
			}}),
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 2},
							{DiffID: lm2DiffID, BaseImageIndex: 1},
							{DiffID: lm3DiffID, BaseImageIndex: 1},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "other",
								},
							},
							{
								{
									Repository: "custom-alpine",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1Enriched, lm2Enriched, lm3Enriched},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "other",
								},
								{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "baseimage",
								},
							},
							{
								{
									Repository: "custom-alpine",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm1ChainID),
									Plugin:     "other",
								},
								{
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
			name: "consecutive_layers_with_same_depsdev_result_and_existing_base_image",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req:  &baseimage.Request{ChainID: lm123ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"nginx"}}},
				},
				{
					req:  &baseimage.Request{ChainID: lm12ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"nginx"}}},
				},
				{
					req:  &baseimage.Request{ChainID: lm1ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"alpine"}}},
				},
			}}),
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
							{DiffID: lm2DiffID, BaseImageIndex: 1},
							{DiffID: lm3DiffID, BaseImageIndex: 1},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{lm1Enriched, lm2Enriched, lm3Enriched},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "other",
								},
								{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "baseimage",
								},
							},
							{
								{
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
			name: "same_depsdev_result_across_existing_base_image_boundary",
			client: mustNewClientFake(t, &config{ReqRespErrs: []reqRespErr{
				{
					req:  &baseimage.Request{ChainID: lm123ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"nginx"}}},
				},
				{
					req:  &baseimage.Request{ChainID: lm12ChainID},
					resp: &baseimage.Response{Results: []*baseimage.Result{{"nginx"}}},
				},
				{
					req: &baseimage.Request{ChainID: lm1ChainID},
				},
			}}),
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 1},
							{DiffID: lm2DiffID, BaseImageIndex: 1},
							{DiffID: lm3DiffID, BaseImageIndex: 0},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm12ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					{
						LayerMetadata: []*extractor.LayerMetadata{
							{DiffID: lm1DiffID, BaseImageIndex: 2},
							{DiffID: lm2DiffID, BaseImageIndex: 2},
							{DiffID: lm3DiffID, BaseImageIndex: 1},
						},
						BaseImages: [][]*extractor.BaseImageDetails{
							{},
							{
								{
									Repository: "nginx",
									Registry:   "docker.io",
									ChainID:    digest.Digest(lm123ChainID),
									Plugin:     "baseimage",
								},
							},
							{
								{
									Repository: "custom-nginx",
									Registry:   "gcr.io",
									ChainID:    digest.Digest(lm12ChainID),
									Plugin:     "other",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enr, err := baseimage.New(configtest.NewFakePluginConfig())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			e := enr.(*baseimage.Enricher)
			e.Client = tc.client
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
