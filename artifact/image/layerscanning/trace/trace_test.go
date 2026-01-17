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
	"fmt"
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
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/opencontainers/go-digest"
)

func TestPopulateLayerDetails(t *testing.T) {
	lm := func(i int) *extractor.LayerMetadata {
		return &extractor.LayerMetadata{
			Index:   i,
			DiffID:  digest.Digest(fmt.Sprintf("sha256:diff-id-%d", i)),
			ChainID: digest.Digest(fmt.Sprintf("sha256:chain-id-%d", i)),
			Command: fmt.Sprintf("command-%d", i),
		}
	}

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
			name: "empty_chain_layers",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
			},
			chainLayers: []image.ChainLayer{},
			wantPackages: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
			},
		},
		{
			name: "package_with_nil_extractor",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
				},
			},
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
			},
			wantPackages: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
				},
			},
		},
		{
			name: "package_in_single_chain_layer",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
				{
					Name:      barPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{barFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
			},
			extractor: fakeLayerExtractor,
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
			},
			wantPackages: []*extractor.Package{
				{
					Name:          fooPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{fooFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(0),
				},
				{
					Name:          barPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{barFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(0),
				},
			},
		},
		{
			name: "package_in_two_chain_layers_-_package_deleted_in_second_layer",
			pkgs: []*extractor.Package{
				{
					Name:      "foo",
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
			},
			extractor: fakeLayerExtractor,
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
			},
			wantPackages: []*extractor.Package{
				{
					Name:          fooPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{fooFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(0),
				},
			},
		},
		{
			name: "packages_in_multiple_chain_layers_-_package_added_in_third_layer",
			pkgs: []*extractor.Package{
				{
					Name:      "foo",
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
				{
					Name:      "baz",
					PURLType:  purl.TypeGeneric,
					Locations: []string{bazFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
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
					Name:          fooPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{fooFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(0),
				},
				{
					Name:          bazPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{bazFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(2),
				},
			},
		},
		{
			name: "packages_in_multiple_chain_layers_-_bar_package_added_back_in_last_layer",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
				{
					Name:      barPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{barFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
				{
					Name:      bazPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{bazFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
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
					Name:          fooPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{fooFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(0),
				},
				{
					Name:          barPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{barFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(3),
				},
				{
					Name:          bazPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{bazFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(2),
				},
			},
		},
		{
			name: "package_in_multiple_chain_layers_-_foo_package_overwritten_in_last_layer",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
				{
					Name:      foo2Package,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
				{
					Name:      barPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{barFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
				{
					Name:      bazPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{bazFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
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
					Name:          fooPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{fooFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(0),
				},
				{
					Name:          foo2Package,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{fooFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(4),
				},
				{
					Name:          barPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{barFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(3),
				},
				{
					Name:          bazPackage,
					PURLType:      purl.TypeGeneric,
					Locations:     []string{bazFile},
					Plugins:       []string{fakeLayerExtractor.Name()},
					LayerMetadata: lm(2),
				},
			},
		},
		{
			name: "chain_layer_with_invalid_diffID",
			pkgs: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
				},
			},
			chainLayers: []image.ChainLayer{
				func() image.ChainLayer {
					tmp := t.TempDir()
					layer, err := fakelayer.New(tmp, digest.Digest(""), "command-0", map[string]string{fooFile: fooPackage}, false)
					if err != nil {
						t.Fatalf("failed creating fake layer: %v", err)
					}
					cfg := &fakechainlayer.Config{
						TestDir:           tmp,
						Index:             0,
						DiffID:            digest.Digest(""),
						ChainID:           digest.Digest("chain-id-invalid"),
						Command:           "command-0",
						Layer:             layer,
						Files:             map[string]string{fooFile: fooPackage},
						FilesAlreadyExist: false,
					}
					cl, err := fakechainlayer.New(cfg)
					if err != nil {
						t.Fatalf("failed creating fake chain layer: %v", err)
					}
					return cl
				}(),
			},
			wantPackages: []*extractor.Package{
				{
					Name:      fooPackage,
					PURLType:  purl.TypeGeneric,
					Locations: []string{fooFile},
					Plugins:   []string{fakeLayerExtractor.Name()},
					LayerMetadata: &extractor.LayerMetadata{
						Index:   0,
						DiffID:  digest.Digest(""),
						ChainID: digest.Digest("chain-id-invalid"),
						Command: "command-0",
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
			inv := inventory.Inventory{Packages: tc.pkgs}
			PopulateLayerDetails(t.Context(), &inv, tc.chainLayers, []filesystem.Extractor{fakeLayerExtractor}, config)
			if diff := cmp.Diff(tc.wantPackages, inv.Packages, cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer")); diff != "" {
				t.Errorf("PopulateLayerDetails(ctx, %v, %v, config) returned an unexpected diff (-want +got): %v", tc.pkgs, tc.chainLayers, diff)
			}
		})
	}
}
