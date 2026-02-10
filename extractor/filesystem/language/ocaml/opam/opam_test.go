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

package opam_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ocaml/opam"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid entry",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.install",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "invalid opam package entry"},
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.install",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "valid file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid.install",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "dune",
					Version:   "3.7.2",
					PURLType:  purl.TypeOpam,
					Locations: []string{"testdata/valid.install"},
				},
				{
					Name:      "ocamlfind",
					Version:   "1.9.6",
					PURLType:  purl.TypeOpam,
					Locations: []string{"testdata/valid.install"},
				},
				{
					Name:      "core_kernel",
					Version:   "0.15.1",
					PURLType:  purl.TypeOpam,
					Locations: []string{"testdata/valid.install"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := opam.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("opam.New: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
