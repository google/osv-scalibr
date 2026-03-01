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

package buildzigzon_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/zig/buildzigzon"
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
			desc: "valid build.zig.zon file",
			path: "/home/user/project/build.zig.zon",
			want: true,
		},
		{
			desc: "invalid file extension",
			path: "/home/user/project/build.zig.zo",
			want: false,
		},
		{
			desc:        "file_size_below_limit",
			path:        "/home/user/project/build.zig.zon",
			fileSize:    1000,
			maxFileSize: 1000,
			want:        true,
		},
		{
			desc:        "file_size_above_limit",
			path:        "/home/user/project/build.zig.zon",
			fileSize:    1001,
			maxFileSize: 1000,
			want:        false,
		},
		{
			desc:                  "override_global_size_below_limit",
			path:                  "/home/user/project/build.zig.zon",
			fileSize:              1001,
			maxFileSize:           1000,
			pluginSpecificMaxSize: 1001,
			want:                  true,
		},
		{
			desc:                  "override_global_size_above_limit",
			path:                  "/home/user/project/build.zig.zon",
			fileSize:              1001,
			maxFileSize:           1001,
			pluginSpecificMaxSize: 1000,
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			e, err := buildzigzon.New(&cpb.PluginConfig{
				MaxFileSizeBytes: tt.maxFileSize,
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{Config: &cpb.PluginSpecificConfig_Buildzigzon{Buildzigzon: &cpb.ZigBuildZigZonConfig{MaxFileSizeBytes: tt.pluginSpecificMaxSize}}},
				},
			})
			if err != nil {
				t.Fatalf("buildzigzon.New(): %v", err)
			}
			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileSize: tt.fileSize,
			})); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractForArtifactMode(t *testing.T) {
	tests := []struct {
		name         string
		inputConfig  extracttest.ScanInputMockConfig
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "valid new version build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/new.build.zig.zon",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "hello_world",
					Version:   "0.0.0",
					PURLType:  purl.TypeZig,
					Locations: []string{"testdata/new.build.zig.zon"},
				},
			},
		},
		{
			name: "valid old version build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/old.build.zig.zon",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "battlebuds",
					Version:   "0.0.1",
					PURLType:  purl.TypeZig,
					Locations: []string{"testdata/old.build.zig.zon"},
				},
			},
		},
		{
			name: "missing name field in build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/withoutname.build.zig.zon",
			},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "missing version field in build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/withoutversion.build.zig.zon",
			},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "invalid build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.build.zig.zon",
			},
			wantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr, err := buildzigzon.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("buildzigzon.New: %v", err)
			}

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

func TestExtractForSourceMode(t *testing.T) {
	tests := []struct {
		name         string
		inputConfig  extracttest.ScanInputMockConfig
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "one dependency build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one.dep.build.zig.zon",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "zigrc",
					Version:   "1.0.0",
					PURLType:  purl.TypeZig,
					Locations: []string{"testdata/one.dep.build.zig.zon"},
				},
			},
		},
		{
			name: "multiple dependency build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple.dep.build.zig.zon",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "zul",
					Version:   "0.0.0",
					PURLType:  purl.TypeZig,
					Locations: []string{"testdata/multiple.dep.build.zig.zon"},
				},
				{
					Name:      "zbor",
					Version:   "0.18.0",
					PURLType:  purl.TypeZig,
					Locations: []string{"testdata/multiple.dep.build.zig.zon"},
				},
				{
					Name:      "wayland",
					Version:   "0.5.0-dev",
					PURLType:  purl.TypeZig,
					Locations: []string{"testdata/multiple.dep.build.zig.zon"},
				},
				{
					Name:      "zm",
					Version:   "0.5.0",
					PURLType:  purl.TypeZig,
					Locations: []string{"testdata/multiple.dep.build.zig.zon"},
				},
			},
		},
		{
			name: "no deps field build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no.deps.build.zig.zon",
			},
			wantErr: extracttest.ContainsErrStr{Str: "could not find .deps"},
		},
		{
			name: "empty deps field build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.deps.build.zig.zon",
			},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "deps field has no extractable dep build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no.valuable.build.zig.zon",
			},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "invalid build.zig.zon file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.build.zig.zon",
			},
			wantErr: extracttest.ContainsErrStr{Str: "could not find .deps"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr, err := buildzigzon.NewWithDeps(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("buildzigzon.NewWithDeps: %v", err)
			}

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
