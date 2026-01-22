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

package baseimageattr_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher/ffa/baseimageattr"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
	"github.com/google/osv-scalibr/inventory"
)

func TestEnrich(t *testing.T) {
	tests := []struct {
		name string
		inv  *inventory.Inventory
		want *inventory.Inventory
	}{
		{
			name: "empty_inventory",
			inv:  &inventory.Inventory{},
			want: &inventory.Inventory{},
		},
		{
			name: "package_not_from_unknownbinaries",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Plugins: []string{"other_plugin"},
						LayerMetadata: &extractor.LayerMetadata{
							BaseImageIndex: 1,
						},
						Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
							Attribution: unknownbinariesextr.Attribution{},
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Plugins: []string{"other_plugin"},
						LayerMetadata: &extractor.LayerMetadata{
							BaseImageIndex: 1,
						},
						Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
							Attribution: unknownbinariesextr.Attribution{},
						},
					},
				},
			},
		},
		{
			name: "no_layer_metadata",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Plugins: []string{unknownbinariesextr.Name},
						Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
							Attribution: unknownbinariesextr.Attribution{},
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Plugins: []string{unknownbinariesextr.Name},
						Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
							Attribution: unknownbinariesextr.Attribution{},
						},
					},
				},
			},
		},
		{
			name: "no_base_image_match",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Plugins: []string{unknownbinariesextr.Name},
						LayerMetadata: &extractor.LayerMetadata{
							BaseImageIndex: 0,
						},
						Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
							Attribution: unknownbinariesextr.Attribution{},
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Plugins: []string{unknownbinariesextr.Name},
						LayerMetadata: &extractor.LayerMetadata{
							BaseImageIndex: 0,
						},
						Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
							Attribution: unknownbinariesextr.Attribution{},
						},
					},
				},
			},
		},
		{
			name: "base_image_match",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Plugins: []string{unknownbinariesextr.Name},
						LayerMetadata: &extractor.LayerMetadata{
							BaseImageIndex: 1,
						},
						Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
							Attribution: unknownbinariesextr.Attribution{},
						},
					},
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Plugins: []string{unknownbinariesextr.Name},
						LayerMetadata: &extractor.LayerMetadata{
							BaseImageIndex: 1,
						},
						Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
							Attribution: unknownbinariesextr.Attribution{
								BaseImage: true,
							},
						},
					},
				},
			},
		},
	}

	e, err := baseimageattr.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("fail to init enricher: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := e.Enrich(t.Context(), nil, tc.inv); err != nil {
				t.Fatalf("Enrich() returned error %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, tc.inv); diff != "" {
				t.Errorf("Enrich() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}
