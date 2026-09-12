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

package gowork_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gowork"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
	}{
		{inputPath: "go.work", want: true},
		{inputPath: "path/to/go.work", want: true},
		{inputPath: "go.work.sum", want: false},
		{inputPath: "go.mod", want: false},
		{inputPath: "go.work.bak", want: false},
		{inputPath: "path/to/go.work/file", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e, err := gowork.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("gowork.New() error: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []*extracttest.TestTableEntry{
		{
			Name: "invalid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.work",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not parse go.work"},
		},
		{
			Name: "no_sum_file_emits_only_stdlib",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.work",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "stdlib",
					Version:  "1.21",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/empty.work", 1),
				},
			},
		},
		{
			Name: "two_modules_with_sum",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-modules.work",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "stdlib",
					Version:  "1.21",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/two-modules.work", 1),
				},
				{
					Name:     "github.com/BurntSushi/toml",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/two-modules.work.sum", 1),
				},
				{
					Name:     "gopkg.in/yaml.v2",
					Version:  "2.4.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/two-modules.work.sum", 3),
				},
			},
		},
		{
			Name: "toolchain_version_takes_priority",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/toolchain.work",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "stdlib",
					Version:  "1.23.6",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/toolchain.work", 3),
				},
			},
		},
		{
			Name: "replace_versioned_target_extracted_local_skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/replace.work",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "stdlib",
					Version:  "1.22",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/replace.work", 1),
				},
				{
					Name:     "example.com/good/thing",
					Version:  "1.4.5",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/replace.work", 5),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := gowork.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("gowork.New() error: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
