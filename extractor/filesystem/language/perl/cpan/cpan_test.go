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

package cpan_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/perl/cpan"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		desc                  string
		path                  string
		fileSize              int64
		maxFileSize           int64
		pluginSpecificMaxSize int64
		want                  bool
	}{
		{
			desc: "valid file",
			path: "/root/.cpanm/work/1770327163.6/URI-5.34/META.json",
			want: true,
		},
		{
			desc: "invalid file extension",
			path: "/root/.cpanm/work/1770327163.6/URI-5.34/META.jso",
			want: false,
		},
		{
			desc: "invalid folder",
			path: "/root/tirpan/work/1770327163.6/URI-5.34/META.json",
			want: false,
		},
		{
			desc: "invalid file",
			path: "/ProgramData/cpan.elf",
			want: false,
		},
		{
			desc:        "file_size_below_limit",
			path:        "/root/.cpanm/work/1770327163.6/URI-5.34/META.json",
			fileSize:    1000,
			maxFileSize: 1000,
			want:        true,
		},
		{
			desc:        "file_size_above_limit",
			path:        "/root/.cpanm/work/1770327163.6/URI-5.34/META.json",
			fileSize:    1001,
			maxFileSize: 1000,
			want:        false,
		},
		{
			desc:                  "override_global_size_below_limit",
			path:                  "/root/.cpanm/work/1770327163.6/URI-5.34/META.json",
			fileSize:              1001,
			maxFileSize:           1000,
			pluginSpecificMaxSize: 1001,
			want:                  true,
		},
		{
			desc:                  "override_global_size_above_limit",
			path:                  "/root/.cpanm/work/1770327163.6/URI-5.34/META.json",
			fileSize:              1001,
			maxFileSize:           1001,
			pluginSpecificMaxSize: 1000,
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			e, err := cpan.New(&cpb.PluginConfig{
				MaxFileSizeBytes: tt.maxFileSize,
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{Config: &cpb.PluginSpecificConfig_Cpan{Cpan: &cpb.PerlCPANConfig{MaxFileSizeBytes: tt.pluginSpecificMaxSize}}},
				},
			})
			if err != nil {
				t.Fatalf("cpan.New(): %v", err)
			}
			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileSize: tt.fileSize,
			})); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		inputConfig  extracttest.ScanInputMockConfig
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "valid META.json file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/META_correct1.json",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "ExtUtils-Helpers",
					Version:   "0.028",
					PURLType:  purl.TypeCPAN,
					Locations: []string{"testdata/META_correct1.json"},
				},
			},
		},
		{
			name: "valid META.json file with lots of dependencies",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/META_correct2.json",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "URI",
					Version:   "5.34",
					PURLType:  purl.TypeCPAN,
					Locations: []string{"testdata/META_correct2.json"},
				},
			},
		},
		{
			name: "missing name field",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/META_withoutname.json",
			},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "missing version field",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/META_withoutversion.json",
			},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "invalid json file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.json",
			},
			wantErr: extracttest.ContainsErrStr{Str: "could not extract"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := cpan.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.inputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfig.Path, diff)
			}
		})
	}
}
