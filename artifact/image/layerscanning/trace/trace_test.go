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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakechainlayer"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayer"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakeextractor"
	"github.com/opencontainers/go-digest"
)

func setupFakeChainLayer(t *testing.T, testDir string, index int, diffID digest.Digest, command string, fileContents map[string]string) *fakechainlayer.FakeChainLayer {
	t.Helper()

	layer := fakelayer.New(diffID, command)
	chainLayer, err := fakechainlayer.New(testDir, index, diffID, command, layer, fileContents, false)
	if err != nil {
		t.Fatalf("fakechainlayer.New(%d, %q, %q, %v, %v) failed: %v", index, diffID, command, layer, fileContents, err)
	}
	return chainLayer
}

func TestPopulateLayerDetails(t *testing.T) {
	const (
		// Fake file names used in tests.
		fooFile = "foo.txt"
		barFile = "bar.txt"
		bazFile = "baz.txt"

		// Fake package names used in tests.
		fooPackage = "foo"
		barPackage = "bar"
		bazPackage = "baz"
	)

	// Chain Layer 1: Start with foo and bar packages.
	// - foo.txt
	// - bar.txt
	digest1 := digest.NewDigestFromEncoded(digest.SHA256, "diff-id-1")
	fakeChainLayer1 := setupFakeChainLayer(t, t.TempDir(), 0, digest1, "command-1", map[string]string{
		fooFile: fooPackage,
		barFile: barPackage,
	})
	fakeExtractor1 := fakeextractor.New("fake-extractor-1", 1, []string{fooFile, barFile}, map[string]fakeextractor.NamesErr{
		fooFile: fakeextractor.NamesErr{
			Names: []string{fooPackage},
		},
		barFile: fakeextractor.NamesErr{
			Names: []string{barPackage},
		},
	})

	// Chain Layer 2: Deletes bar package.
	// - foo.txt
	digest2 := digest.NewDigestFromEncoded(digest.SHA256, "diff-id-2")
	fakeChainLayer2 := setupFakeChainLayer(t, t.TempDir(), 1, digest2, "command-2", map[string]string{
		fooFile: fooPackage,
	})
	fakeExtractor2 := fakeextractor.New("fake-extractor-2", 1, []string{fooFile}, map[string]fakeextractor.NamesErr{
		fooFile: fakeextractor.NamesErr{
			Names: []string{fooPackage},
		},
	})

	// Chain Layer 3: Adds baz package.
	// - foo.txt
	// - baz.txt
	digest3 := digest.NewDigestFromEncoded(digest.SHA256, "diff-id-3")
	fakeChainLayer3 := setupFakeChainLayer(t, t.TempDir(), 2, digest3, "command-3", map[string]string{
		fooFile: fooPackage,
		bazFile: bazPackage,
	})
	fakeExtractor3 := fakeextractor.New("fake-extractor-3", 1, []string{fooFile, bazFile}, map[string]fakeextractor.NamesErr{
		fooFile: fakeextractor.NamesErr{
			Names: []string{fooPackage},
		},
		bazFile: fakeextractor.NamesErr{
			Names: []string{bazPackage},
		},
	})

	// Chain Layer 4: Adds bar package back.
	// - foo.txt
	// - bar.txt
	// - baz.txt
	digest4 := digest.NewDigestFromEncoded(digest.SHA256, "diff-id-4")
	fakeChainLayer4 := setupFakeChainLayer(t, t.TempDir(), 3, digest4, "command-4", map[string]string{
		fooFile: fooPackage,
		barFile: barPackage,
		bazFile: bazPackage,
	})
	fakeExtractor4 := fakeextractor.New("fake-extractor-4", 1, []string{fooFile, barFile, bazFile}, map[string]fakeextractor.NamesErr{
		fooFile: fakeextractor.NamesErr{
			Names: []string{fooPackage},
		},
		barFile: fakeextractor.NamesErr{
			Names: []string{barPackage},
		},
		bazFile: fakeextractor.NamesErr{
			Names: []string{bazPackage},
		},
	})

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
			name: "inventory in single chain layer",
			inventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeExtractor1,
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeExtractor1,
				},
			},
			extractor: fakeExtractor1,
			chainLayers: []image.ChainLayer{
				fakeChainLayer1,
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeExtractor1,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-1",
						Command:     "command-1",
						InBaseImage: false,
					},
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeExtractor1,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-1",
						Command:     "command-1",
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
					Extractor: fakeExtractor2,
				},
			},
			extractor: fakeExtractor2,
			chainLayers: []image.ChainLayer{
				fakeChainLayer1,
				fakeChainLayer2,
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeExtractor2,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-1",
						Command:     "command-1",
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
					Extractor: fakeExtractor3,
				},
				{
					Name:      "baz",
					Locations: []string{bazFile},
					Extractor: fakeExtractor3,
				},
			},
			extractor: fakeExtractor3,
			chainLayers: []image.ChainLayer{
				fakeChainLayer1,
				fakeChainLayer2,
				fakeChainLayer3,
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeExtractor3,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-1",
						Command:     "command-1",
						InBaseImage: false,
					},
				},
				{
					Name:      bazPackage,
					Locations: []string{bazFile},
					Extractor: fakeExtractor3,
					LayerDetails: &extractor.LayerDetails{
						Index:       2,
						DiffID:      "diff-id-3",
						Command:     "command-3",
						InBaseImage: false,
					},
				},
			},
		},
		{
			name: "inventory in multiple chain layers - bar package added back in last layer",
			inventory: []*extractor.Inventory{
				{
					Name:      "foo",
					Locations: []string{fooFile},
					Extractor: fakeExtractor4,
				},
				{
					Name:      "bar",
					Locations: []string{barFile},
					Extractor: fakeExtractor4,
				},
				{
					Name:      "baz",
					Locations: []string{bazFile},
					Extractor: fakeExtractor4,
				},
			},
			extractor: fakeExtractor4,
			chainLayers: []image.ChainLayer{
				fakeChainLayer1,
				fakeChainLayer2,
				fakeChainLayer3,
				fakeChainLayer4,
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      fooPackage,
					Locations: []string{fooFile},
					Extractor: fakeExtractor4,
					LayerDetails: &extractor.LayerDetails{
						Index:       0,
						DiffID:      "diff-id-1",
						Command:     "command-1",
						InBaseImage: false,
					},
				},
				{
					Name:      barPackage,
					Locations: []string{barFile},
					Extractor: fakeExtractor4,
					LayerDetails: &extractor.LayerDetails{
						Index:       3,
						DiffID:      "diff-id-4",
						Command:     "command-4",
						InBaseImage: false,
					},
				},
				{
					Name:      bazPackage,
					Locations: []string{bazFile},
					Extractor: fakeExtractor4,
					LayerDetails: &extractor.LayerDetails{
						Index:       2,
						DiffID:      "diff-id-3",
						Command:     "command-3",
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
				FilesToExtract: []string{"Installed"},
				Extractors:     []filesystem.Extractor{tc.extractor},
			}

			PopulateLayerDetails(t.Context(), tc.inventory, tc.chainLayers, config)
			if diff := cmp.Diff(tc.wantInventory, tc.inventory, cmpopts.IgnoreFields(extractor.Inventory{}, "Extractor")); diff != "" {
				t.Errorf("PopulateLayerDetails(ctx, %v, %v, config) returned an unexpected diff (-want +got): %v", tc.inventory, tc.chainLayers, diff)
			}
		})
	}
}

func TestAreInventoriesEqual(t *testing.T) {
	tests := []struct {
		name string
		inv1 *extractor.Inventory
		inv2 *extractor.Inventory
		want bool
	}{
		{
			name: "nil extractor",
			inv1: &extractor.Inventory{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: nil,
			},
			inv2: &extractor.Inventory{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: nil,
			},
			want: false,
		},
		{
			name: "same inventory",
			inv1: &extractor.Inventory{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			inv2: &extractor.Inventory{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			want: true,
		},
		{
			name: "same inventory with multiple locations",
			inv1: &extractor.Inventory{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt", "another-foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			inv2: &extractor.Inventory{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"another-foo.txt", "foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			want: true,
		},
		{
			name: "different name",
			inv1: &extractor.Inventory{
				Name:      "foo",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			inv2: &extractor.Inventory{
				Name:      "bar",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			want: false,
		},
		{
			name: "different version",
			inv1: &extractor.Inventory{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			inv2: &extractor.Inventory{
				Name:      "foo",
				Version:   "2.0",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			want: false,
		},
		{
			name: "different locations",
			inv1: &extractor.Inventory{
				Name:      "foo",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			inv2: &extractor.Inventory{
				Name:      "foo",
				Locations: []string{"another-foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := areInventoriesEqual(tc.inv1, tc.inv2); got != tc.want {
				t.Errorf("areInventoriesEqual(%v, %v) = %v, want: %v", tc.inv1, tc.inv2, got, tc.want)
			}
		})
	}
}
