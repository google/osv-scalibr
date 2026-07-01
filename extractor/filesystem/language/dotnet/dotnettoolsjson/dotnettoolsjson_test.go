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

package dotnettoolsjson_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/dotnettoolsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
	}{
		{
			inputPath: "dotnet-tools.json",
			want:      true,
		},
		{
			inputPath: "path/to/.config/dotnet-tools.json",
			want:      true,
		},
		{
			inputPath: "dotnet-tools.json.bak",
			want:      false,
		},
		{
			inputPath: "tools.json",
			want:      false,
		},
		{
			inputPath: "",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e, err := dotnettoolsjson.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("dotnettoolsjson.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "empty tools",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty",
			},
			WantPackages: nil,
		},
		{
			Name: "basic tools",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cake.tool",
					Version:  "5.0.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "powershell",
					Version:  "7.1.2",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
			},
		},
		{
			Name: "malformed json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "failed to decode JSON"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := dotnettoolsjson.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("dotnettoolsjson.New: %v", err)
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
