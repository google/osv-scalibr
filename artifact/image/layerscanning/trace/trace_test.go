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

package trace

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayerbuilder"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/stats"
)

func TestPopulateLayerDetails(t *testing.T) {
	const (
		// Fake file names used in tests.
		fooFile = "foo.txt"
		barFile = "bar.txt"
		bazFile = "baz.txt"

		// Fake package names used in tests.
		fooPackage  = "foo"
		foo2Package = "foo2"
		barPackage  = "bar"
		bazPackage  = "baz"
	)

	fakeLayerExtractor := fakelayerbuilder.FakeTestLayersExtractor{}
	fakeChainLayers := fakelayerbuilder.BuildFakeChainLayersFromPath(t, t.TempDir(), "testdata/populatelayers.yml")

	tests := []struct {
		name          string
		inventory     []*extractor.Inventory
		extractor     filesystem.Extractor
		chainLayers   []image.ChainLayer
		wantInventory []*extractor.Inventory
	}{
		{
			name:          "empty inventory",
			inventory:     []*extractor.Inventory{},
			chainLayers:   []image.ChainLayer{},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "empty chain layers",
			inventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
			},
			chainLayers: []image.ChainLayer{},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
			},
		},
		{
			name: "inventory with nil extractor",
			inventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
				},
			},
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
				},
			},
		},
		{
			name: "inventory in single chain layer",
			inventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeLayerExtractor,
				},
			},
			extractor: fakeLayerExtractor,
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-0",
						Command:     "command-0",
						InBaseImage: false,
					},
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-0",
						Command:     "command-0",
						InBaseImage: false,
					},
				},
			},
		},
		{
			name: "inventory in two chain layers - package deleted in second layer",
			inventory: []*extractor.Inventory{
				{
					Name:      "foo",
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
			},
			extractor: fakeLayerExtractor,
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-0",
						Command:     "command-0",
						InBaseImage: false,
					},
				},
			},
		},
		{
			name: "inventory in multiple chain layers - package added in third layer",
			inventory: []*extractor.Inventory{
				{
					Name:      "foo",
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
				{
					Name:      "baz",
					Locations: []string{bazFile},
					Extractor: fakeLayerExtractor,
				},
			},
			extractor: fakeLayerExtractor,
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
				fakeChainLayers[2],
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-0",
						Command:     "command-0",
						InBaseImage: false,
					},
				},
				{
					Name:      bazPackage,
					Locations: []string{bazFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       2,
						DiffID:      "diff-id-2",
						Command:     "command-2",
						InBaseImage: false,
					},
				},
			},
		},
		{
			name: "inventory in multiple chain layers - bar package added back in last layer",
			inventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeLayerExtractor,
				},
				{
					Name:      bazPackage,
					Locations: []string{bazFile},
					Extractor: fakeLayerExtractor,
				},
			},
			extractor: fakeLayerExtractor,
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
				fakeChainLayers[2],
				fakeChainLayers[3],
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-0",
						Command:     "command-0",
						InBaseImage: false,
					},
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       3,
						DiffID:      "diff-id-3",
						Command:     "command-3",
						InBaseImage: false,
					},
				},
				{
					Name:      bazPackage,
					Locations: []string{bazFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       2,
						DiffID:      "diff-id-2",
						Command:     "command-2",
						InBaseImage: false,
					},
				},
			},
		},
		{
			name: "inventory in multiple chain layers - foo package overwritten in last layer",
			inventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
				{
					Name:      foo2Package,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeLayerExtractor,
				},
				{
					Name:      bazPackage,
					Locations: []string{bazFile},
					Extractor: fakeLayerExtractor,
				},
			},
			extractor: fakeLayerExtractor,
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
				fakeChainLayers[2],
				fakeChainLayers[3],
				fakeChainLayers[4],
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-0",
						Command:     "command-0",
						InBaseImage: false,
					},
				},
				{
					Name:      foo2Package,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       4,
						DiffID:      "diff-id-4",
						Command:     "command-4",
						InBaseImage: false,
					},
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       3,
						DiffID:      "diff-id-3",
						Command:     "command-3",
						InBaseImage: false,
					},
				},
				{
					Name:      bazPackage,
					Locations: []string{bazFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       2,
						DiffID:      "diff-id-2",
						Command:     "command-2",
						InBaseImage: false,
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &filesystem.Config{
				Stats:          stats.NoopCollector{},
				PathsToExtract: []string{"Installed"},
				Extractors:     []filesystem.Extractor{tc.extractor},
			}

			PopulateLayerDetails(context.Background(), tc.inventory, tc.chainLayers, config)
			if diff := cmp.Diff(tc.wantInventory, tc.inventory, cmpopts.IgnoreFields(extractor.Inventory{}, "Extractor")); diff != "" {
				t.Errorf("PopulateLayerDetails(ctx, %v, %v, config) returned an unexpected diff (-want +got): %v", tc.inventory, tc.chainLayers, diff)
			}
		})
	}
}
