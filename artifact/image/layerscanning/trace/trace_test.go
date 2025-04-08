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
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakechainlayer"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayer"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayerbuilder"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/stats"
	"github.com/opencontainers/go-digest"
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
		name         string
		pkgs         []*extractor.Package
		extractor    filesystem.Extractor
		chainLayers  []image.ChainLayer
		wantPackages []*extractor.Package
	}{
		{
			name:         "empty package",
			pkgs:         []*extractor.Package{},
			chainLayers:  []image.ChainLayer{},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "empty chain layers",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
			},
			chainLayers: []image.ChainLayer{},
			wantPackages: []*extractor.Package{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
			},
		},
		{
			name: "package with nil extractor",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
				},
			},
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
			},
			wantPackages: []*extractor.Package{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
				},
			},
		},
		{
			name: "package in single chain layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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
			name: "package in two chain layers - package deleted in second layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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
			name: "packages in multiple chain layers - package added in third layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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
			name: "packages in multiple chain layers - bar package added back in last layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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
			name: "package in multiple chain layers - foo package overwritten in last layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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
		{
			name: "chain layer with invalid diffID",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
				},
			},
			chainLayers: []image.ChainLayer{
				func() image.ChainLayer {
					tmp := t.TempDir()
					layer, err := fakelayer.New(tmp, digest.Digest(""), "command-0", map[string]string{fooFile: fooPackage}, false)
					if err != nil {
						t.Fatalf("failed creating fake layer: %v", err)
					}
					cl, err := fakechainlayer.New(tmp, 0, digest.Digest(""), "command-0", layer, map[string]string{fooFile: fooPackage}, false)
					if err != nil {
						t.Fatalf("failed creating fake chain layer: %v", err)
					}
					return cl
				}(),
			},
			wantPackages: []*extractor.Package{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeLayerExtractor,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "",
						Command:     "command-0",
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

			PopulateLayerDetails(context.Background(), inventory.Inventory{Packages: tc.pkgs}, tc.chainLayers, config)
			if diff := cmp.Diff(tc.wantPackages, tc.pkgs, cmpopts.IgnoreFields(extractor.Package{}, "Extractor")); diff != "" {
				t.Errorf("PopulateLayerDetails(ctx, %v, %v, config) returned an unexpected diff (-want +got): %v", tc.pkgs, tc.chainLayers, diff)
			}
		})
	}
}
