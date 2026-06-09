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

package vendormodules_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/vendormodules"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "empty",
			inputPath: "",
			want:      false,
		},
		{
			name:      "root_vendor_modules",
			inputPath: "vendor/modules.txt",
			want:      true,
		},
		{
			name:      "nested_vendor_modules",
			inputPath: "path/to/vendor/modules.txt",
			want:      true,
		},
		{
			name:      "windows_vendor_modules",
			inputPath: `path\to\vendor\modules.txt`,
			want:      true,
		},
		{
			name:      "modules_txt_outside_vendor",
			inputPath: "path/to/modules.txt",
			want:      false,
		},
		{
			name:      "other_file_in_vendor",
			inputPath: "path/to/vendor/other.txt",
			want:      false,
		},
		{
			name:      "vendor_modules_child",
			inputPath: "path/to/vendor/modules.txt/file",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := vendormodules.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("vendormodules.New() error: %v", err)
			}

			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) got %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []*extracttest.TestTableEntry{
		{
			Name: "valid_modules",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid/vendor/modules.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "example.com/afterheaderonly",
					Version:  "0.3.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine(
						"testdata/valid/vendor/modules.txt", 26),
				},
				{
					Name:     "github.com/BurntSushi/toml",
					Version:  "1.2.1",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine(
						"testdata/valid/vendor/modules.txt", 1),
				},
				{
					Name:     "golang.org/x/crypto",
					Version:  "0.31.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine(
						"testdata/valid/vendor/modules.txt", 4),
				},
				{
					Name:     "example.com/fork/net",
					Version:  "1.4.5",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine(
						"testdata/valid/vendor/modules.txt", 7),
				},
				{
					Name:     "example.com/local",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine(
						"testdata/valid/vendor/modules.txt", 10),
				},
				{
					Name:     "example.com/transitive",
					Version:  "0.2.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine(
						"testdata/valid/vendor/modules.txt", 18),
				},
				{
					Name:     "example.com/wildcard-fork",
					Version:  "0.2.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine(
						"testdata/valid/vendor/modules.txt", 29),
				},
				{
					Name:     "github.com/example/incompatible",
					Version:  "2.0.0+incompatible",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine(
						"testdata/valid/vendor/modules.txt", 15),
				},
			},
		},
		{
			Name: "empty_file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty/vendor/modules.txt",
			},
			WantPackages: nil,
		},
		{
			Name: "invalid_modules",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/vendor/modules.txt",
			},
			WantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := vendormodules.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("vendormodules.New() error: %v", err)
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

func TestExtractor_Extract_ContextCancelled(t *testing.T) {
	extr, err := vendormodules.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("vendormodules.New() error: %v", err)
	}

	scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/valid/vendor/modules.txt",
	})
	defer extracttest.CloseTestScanInput(t, scanInput)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = extr.Extract(ctx, &scanInput)
	if err == nil || !strings.Contains(err.Error(), "context error") {
		t.Fatalf("%s.Extract() error got %v, want context error", extr.Name(), err)
	}
}
