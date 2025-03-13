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
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakeextractor"
	"github.com/opencontainers/go-digest"
)

func setupFakeChainLayer(t *testing.T, testDir string, index int, diffID digest.Digest, command string, layerContents map[string]string, chainLayerContents map[string]string) *fakechainlayer.FakeChainLayer {
	t.Helper()

	layer, err := fakelayer.New(testDir, diffID, command, layerContents, false)
	if err != nil {
		t.Fatalf("fakelayer.New(%q, %q, %q, %v, %v) failed: %v", testDir, diffID, command, layerContents, false, err)
	}

	chainLayer, err := fakechainlayer.New(testDir, index, diffID, command, layer, chainLayerContents, false)
	if err != nil {
		t.Fatalf("fakechainlayer.New(%d, %q, %q, %v, %v) failed: %v", index, diffID, command, layer, chainLayerContents, err)
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
	layerContents1 := map[string]string{
		fooFile: fooPackage,
		barFile: barPackage,
	}
	chainLayerContents1 := map[string]string{
		fooFile: fooPackage,
		barFile: barPackage,
	}
	digest1 := digest.NewDigestFromEncoded(digest.SHA256, "diff-id-1")
	fakeChainLayer1 := setupFakeChainLayer(t, t.TempDir(), 0, digest1, "command-1", layerContents1, chainLayerContents1)
	fakeExtractor1 := fakeextractor.New("fake-extractor-1", 1, []string{fooFile, barFile}, map[string]fakeextractor.NamesErr{
		fooFile: fakeextractor.NamesErr{
			Names: []string{fooPackage},
		},
		barFile: fakeextractor.NamesErr{
			Names: []string{barPackage},
		},
	})

	layerContents2 := map[string]string{}
	chainLayerContents2 := map[string]string{
		fooFile: fooPackage,
	}
	// Chain Layer 2: Deletes bar package.
	// - foo.txt
	digest2 := digest.NewDigestFromEncoded(digest.SHA256, "diff-id-2")
	fakeChainLayer2 := setupFakeChainLayer(t, t.TempDir(), 1, digest2, "command-2", layerContents2, chainLayerContents2)
	fakeExtractor2 := fakeextractor.New("fake-extractor-2", 1, []string{fooFile}, map[string]fakeextractor.NamesErr{
		fooFile: fakeextractor.NamesErr{
			Names: []string{fooPackage},
		},
	})

	// Chain Layer 3: Adds baz package.
	// - foo.txt
	// - baz.txt
	layerContents3 := map[string]string{
		bazFile: bazPackage,
	}
	chainLayerContents3 := map[string]string{
		fooFile: fooPackage,
		bazFile: bazPackage,
	}
	digest3 := digest.NewDigestFromEncoded(digest.SHA256, "diff-id-3")
	fakeChainLayer3 := setupFakeChainLayer(t, t.TempDir(), 2, digest3, "command-3", layerContents3, chainLayerContents3)
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
	layerContents4 := map[string]string{
		barFile: barPackage,
	}
	chainLayerContents4 := map[string]string{
		fooFile: fooPackage,
		barFile: barPackage,
		bazFile: bazPackage,
	}
	digest4 := digest.NewDigestFromEncoded(digest.SHA256, "diff-id-4")
	fakeChainLayer4 := setupFakeChainLayer(t, t.TempDir(), 3, digest4, "command-4", layerContents4, chainLayerContents4)
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
			name: "package in single chain layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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
			name: "package in two chain layers - package deleted in second layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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
			name: "packages in multiple chain layers - package added in third layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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
			name: "packages in multiple chain layers - bar package added back in last layer",
			pkgs: []*extractor.Package{
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
			wantPackages: []*extractor.Package{
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

			inv := inventory.Inventory{Packages: tc.pkgs}
			PopulateLayerDetails(context.Background(), inv, tc.chainLayers, config)
			if diff := cmp.Diff(tc.wantPackages, inv.Packages, cmpopts.IgnoreFields(extractor.Package{}, "Extractor")); diff != "" {
				t.Errorf("PopulateLayerDetails(ctx, %v, %v, config) returned an unexpected diff (-want +got): %v", tc.pkgs, tc.chainLayers, diff)
			}
		})
	}
}

func TestArePackagesEqual(t *testing.T) {
	tests := []struct {
		name string
		pkg1 *extractor.Package
		pkg2 *extractor.Package
		want bool
	}{
		{
			name: "nil extractor",
			pkg1: &extractor.Package{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: nil,
			},
			pkg2: &extractor.Package{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: nil,
			},
			want: false,
		},
		{
			name: "same package",
			pkg1: &extractor.Package{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			pkg2: &extractor.Package{
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
			name: "same package with multiple locations",
			pkg1: &extractor.Package{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt", "another-foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			pkg2: &extractor.Package{
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
			pkg1: &extractor.Package{
				Name:      "foo",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			pkg2: &extractor.Package{
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
			pkg1: &extractor.Package{
				Name:      "foo",
				Version:   "1.0",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			pkg2: &extractor.Package{
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
			pkg1: &extractor.Package{
				Name:      "foo",
				Locations: []string{"foo.txt"},
				Extractor: fakeextractor.New("fake-extractor", 1, []string{"foo.txt"}, map[string]fakeextractor.NamesErr{
					"foo.txt": fakeextractor.NamesErr{
						Names: []string{"foo"},
					},
				}),
			},
			pkg2: &extractor.Package{
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
			if got := arePackagesEqual(tc.pkg1, tc.pkg2); got != tc.want {
				t.Errorf("arePackagesEqual(%v, %v) = %v, want: %v", tc.pkg1, tc.pkg2, got, tc.want)
			}
		})
	}
}
