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
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/imagedsl"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/config/configtest"
	"google.golang.org/protobuf/testing/protocmp"
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
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("Requirements() returned diff (-want +got):\n%s", diff)
	}
}

func TestRequiredPlugins(t *testing.T) {
	e := &baseimage.Enricher{}
	got := e.RequiredPlugins()
	want := []string{}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("RequiredPlugins() returned diff (-want +got):\n%s", diff)
	}
}

func TestEnrich(t *testing.T) {
	clientErr := errors.New("client error")

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:  "no_image_metadata_to_enrich",
			input: ``,
			want:  ``,
		},
		{
			name: "enrich_layers",
			input: `
				layer alpine       depsdev=alpine
				layer nginxnonedge
				layer nginx        depsdev=nginx
			`,
			want: `
				layer alpine
				=== base docker.io/alpine ===
				layer nginxnonedge
				layer nginx
				=== base docker.io/nginx ===
			`,
		},
		{
			name: "enrich_with_empty_layer_and_multiple_repos",
			input: `
				layer alpine
				empty-layer depsdev=alpine,alpine-mirror
				layer app
			`,
			want: `
				layer alpine
				empty-layer
				=== base docker.io/alpine ===
				=== base docker.io/alpine-mirror ===
				layer app
			`,
		},
		{
			name: "same_layer_chainID_in_different_images_should_use_cache",
			input: `
				image
				layer alpine depsdev=alpine

				image
				layer alpine depsdev=CACHED
			`,
			want: `
				image
				layer alpine
				=== base docker.io/alpine ===

				image
				layer alpine
				=== base docker.io/alpine ===
			`,
		},
		{
			name: "client_error_on_last_layer",
			input: `
				layer alpine       depsdev=alpine
				layer nginxnonedge
				layer clienterror  depsdev=ERROR
			`,
			// When a query fails, none of the image's layers are enriched.
			want: `
				layer alpine
				layer nginxnonedge
				layer clienterror
			`,
			wantErr: clientErr,
		},
		{
			name: "client_error_on_first_layer",
			input: `
				layer clienterror  depsdev=ERROR
				layer nginxnonedge
				layer nginx        depsdev=nginx
			`,
			want: `
				layer clienterror
				layer nginxnonedge
				layer nginx
			`,
			wantErr: clientErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputSpec := imagedsl.MustParse(t, tc.input)
			wantSpec := imagedsl.MustParse(t, tc.want)

			enr, err := baseimage.New(configtest.NewFakePluginConfig())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			e := enr.(*baseimage.Enricher)
			fakeClient := mustClientFromSpec(t, inputSpec, clientErr)
			e.Client = fakeClient

			inv := inputSpec.ToInventory()
			wantInv := wantSpec.ToEnrichedInventory()

			gotErr := e.Enrich(t.Context(), nil, inv)
			if !cmp.Equal(gotErr, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("Enrich() error = %v, want %v", gotErr, tc.wantErr)
			}
			fakeClient.AssertExpectations(t, tc.wantErr != nil)

			opts := append([]cmp.Option{protocmp.Transform()}, imagedsl.DiffOptions()...)
			if diff := cmp.Diff(wantInv, inv, opts...); diff != "" {
				t.Errorf("Enrich() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}
