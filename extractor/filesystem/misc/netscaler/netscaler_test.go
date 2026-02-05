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

package netscaler_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/netscaler"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	extractor, err := netscaler.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("netscaler.New failed: %v", err)
	}
	tests := []struct {
		path string
		want bool
	}{
		{"testdata/ns.conf", true},
		{"testdata/loader.conf", true},
		{"testdata/nsversion", true},
		{"testdata/NS.CONF", true},
		{"testdata/LOADER.CONF", true},
		{"testdata/NSVERSION", true},
		{"testdata/ns-12.1-44.50.gz", true},
		{"testdata/document.txt", false},
		{"testdata/noextension", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := extractor.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	wdir, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get current working directory")
	}

	tests := []extracttest.TestTableEntry{
		{
			Name: "NetScaler valid loader.conf",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid/loader.conf",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "NetScaler",
					Version:   "14.1-36.5",
					Locations: []string{"testdata/valid/loader.conf"},
					Metadata:  os.DirFS(wdir).(scalibrfs.FS),
				},
			},
		},
		{
			Name: "NetScaler valid nsversion",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid/nsversion",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "NetScaler",
					Version:   "13.1-59.21",
					Locations: []string{"testdata/valid/nsversion"},
					Metadata:  os.DirFS(wdir).(scalibrfs.FS),
				},
			},
		},
		{
			Name: "NetScaler valid ns.conf",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid/ns.conf",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "NetScaler",
					Version:   "12.1-55.329",
					Locations: []string{"testdata/valid/ns.conf"},
					Metadata:  os.DirFS(wdir).(scalibrfs.FS),
				},
			},
		},
		{
			Name: "NetScaler invalid loader.conf",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/loader.conf",
			},
			WantPackages: nil,
		},
		{
			Name: "NetScaler invalid nsversion",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/nsversion",
			},
			WantPackages: nil,
		},
		{
			Name: "NetScaler invalid ns.conf",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/ns.conf",
			},
			WantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := netscaler.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("netscaler.New failed: %v", err)
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
