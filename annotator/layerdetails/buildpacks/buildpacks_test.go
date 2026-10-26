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

package buildpacks_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/annotator/layerdetails/buildpacks"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestAnnotate(t *testing.T) {
	const lifecycleMetadataJSON = `{
		"app": [
			{"sha": "sha256:diff-id-6"},
			{"sha": "sha256:diff-id-shared"}
		],
		"sbom": {"sha": "sha256:diff-id-5"},
		"buildpacks": [
			{
				"key": "example.runtime",
				"version": "0.0.0",
				"layers": {}
			},
			{
				"key": "example.framework",
				"version": "1.2.3",
				"layers": {
					"framework": {"sha": "sha256:diff-id-3"}
				}
			},
			{
				"key": "example.build",
				"version": "1.0.0",
				"layers": {
					"bin": {"sha": "sha256:diff-id-4"},
					"shared": {"sha": "sha256:diff-id-shared"}
				}
			}
		],
		"config": {"sha": "sha256:diff-id-8"},
		"launcher": {"sha": "sha256:diff-id-7"}
	}`

	tests := []struct {
		name    string
		inv     *inventory.Inventory
		want    *inventory.Inventory
		wantErr error
	}{
		{
			name: "no_buildpacks_label",
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
					Labels: map[string]string{"other": "value"},
					LayerMetadata: []*extractor.LayerMetadata{
						{Index: 0, DiffID: "sha256:diff-id-0"},
					},
				}},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
					Labels: map[string]string{"other": "value"},
					LayerMetadata: []*extractor.LayerMetadata{
						{Index: 0, DiffID: "sha256:diff-id-0"},
					},
				}},
			},
		},
		{
			name: "empty_buildpacks_label_is_ignored",
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
					Labels: map[string]string{"io.buildpacks.lifecycle.metadata": ""},
					LayerMetadata: []*extractor.LayerMetadata{
						{Index: 0, DiffID: "sha256:diff-id-0"},
					},
				}},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
					Labels: map[string]string{"io.buildpacks.lifecycle.metadata": ""},
					LayerMetadata: []*extractor.LayerMetadata{
						{Index: 0, DiffID: "sha256:diff-id-0"},
					},
				}},
			},
		},
		{
			name: "invalid_json_returns_error",
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
					Labels: map[string]string{
						"io.buildpacks.lifecycle.metadata": "{invalid",
					},
				}},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			name: "attaches_buildpacks_role_tags_by_diff_id",
			inv: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
					Labels: map[string]string{
						"io.buildpacks.lifecycle.metadata": lifecycleMetadataJSON,
					},
					LayerMetadata: []*extractor.LayerMetadata{
						{Index: 0, DiffID: "sha256:diff-id-0"},
						{Index: 3, DiffID: "sha256:diff-id-3"},
						{Index: 4, DiffID: "sha256:diff-id-4"},
						{Index: 5, DiffID: "sha256:diff-id-5"},
						{Index: 6, DiffID: "sha256:diff-id-6", Attributes: createAttributes("existing")},
						{Index: 7, DiffID: "sha256:diff-id-7"},
						{Index: 8, DiffID: "sha256:diff-id-8"},
						{Index: 9, DiffID: "sha256:diff-id-9"},
						{Index: 10, DiffID: "sha256:diff-id-shared"},
					},
				}},
			},
			want: &inventory.Inventory{
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
					Labels: map[string]string{
						"io.buildpacks.lifecycle.metadata": lifecycleMetadataJSON,
					},
					LayerMetadata: []*extractor.LayerMetadata{{
						Index:  0,
						DiffID: "sha256:diff-id-0",
					}, {
						Index:  3,
						DiffID: "sha256:diff-id-3",
						Attributes: createAttributes(
							"buildpacks/buildpack/example.framework/framework",
						),
					}, {
						Index:      4,
						DiffID:     "sha256:diff-id-4",
						Attributes: createAttributes("buildpacks/buildpack/example.build/bin"),
					}, {
						Index:      5,
						DiffID:     "sha256:diff-id-5",
						Attributes: createAttributes("buildpacks/sbom"),
					}, {
						Index:      6,
						DiffID:     "sha256:diff-id-6",
						Attributes: createAttributes("existing", "buildpacks/app"),
					}, {
						Index:      7,
						DiffID:     "sha256:diff-id-7",
						Attributes: createAttributes("buildpacks/launcher"),
					}, {
						Index:      8,
						DiffID:     "sha256:diff-id-8",
						Attributes: createAttributes("buildpacks/config"),
					}, {
						Index:  9,
						DiffID: "sha256:diff-id-9",
					}, {
						Index:  10,
						DiffID: "sha256:diff-id-shared",
						Attributes: createAttributes(
							"buildpacks/app",
							"buildpacks/buildpack/example.build/shared",
						),
					}},
				}},
			},
		},
	}

	plugin, err := buildpacks.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("buildpacks.New() unexpected error: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := plugin.Annotate(t.Context(), nil, tc.inv)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Annotate() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if diff := cmp.Diff(tc.want, tc.inv); diff != "" {
				t.Errorf("Annotate() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func createAttributes(tags ...string) []*extractor.LayerAttribute {
	var attrs []*extractor.LayerAttribute
	for _, tag := range tags {
		attrs = append(attrs, &extractor.LayerAttribute{
			Value:  tag,
			Plugin: buildpacks.Name,
		})
	}
	return attrs
}
