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

package pulumiyaml_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/pulumi/pulumiyaml"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
	}{
		{
			name:         "Pulumi.yaml at root",
			path:         "Pulumi.yaml",
			wantRequired: true,
		},
		{
			name:         "Pulumi.yml in subdir",
			path:         "path/to/Pulumi.yml",
			wantRequired: true,
		},
		{
			name:         "not Pulumi.yaml",
			path:         "main.go",
			wantRequired: false,
		},
		{
			name:         "similar name but not exact",
			path:         "pulumi.yaml",
			wantRequired: false,
		},
		{
			name:         "another similar name",
			path:         "Pulumi.yaml.backup",
			wantRequired: false,
		},
		{
			name:             "Pulumi.yaml required if size less than maxFileSizeBytes",
			path:             "Pulumi.yaml",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 2000 * units.MiB,
			wantRequired:     true,
		},
		{
			name:             "Pulumi.yaml required if size equal to maxFileSizeBytes",
			path:             "Pulumi.yaml",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     true,
		},
		{
			name:             "Pulumi.yaml not required if size greater than maxFileSizeBytes",
			path:             "Pulumi.yaml",
			fileSizeBytes:    10000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     false,
		},
		{
			name:             "Pulumi.yaml required if maxFileSizeBytes explicitly set to 0",
			path:             "Pulumi.yaml",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := pulumiyaml.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("pulumiyaml.New: %v", err)
			}

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1 * units.KiB
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []*extracttest.TestTableEntry{
		{
			Name: "valid file with multiple providers",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "aws",
					Version:  "6.0.0",
					Location: extractor.LocationFromPathAndLine("testdata/valid.yaml", 6),
					PURLType: "",
				},
				{
					Name:     "kubernetes",
					Version:  "4.0.0",
					Location: extractor.LocationFromPathAndLine("testdata/valid.yaml", 8),
					PURLType: "",
				},
			},
		},
		{
			Name: "single provider",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/single-provider.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "gcp",
					Version:  "7.0.0",
					Location: extractor.LocationFromPathAndLine("testdata/single-provider.yaml", 6),
					PURLType: "",
				},
			},
		},
		{
			Name: "no version should skip provider",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-version.yaml",
			},
			WantPackages: nil,
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.yaml",
			},
			WantPackages: nil,
		},
		{
			Name: "malformed file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed.yaml",
			},
			WantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			e, err := pulumiyaml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pulumiyaml.New: %v", err)
			}
			got, err := e.Extract(t.Context(), &scanInput)
			if !cmp.Equal(err, tt.WantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.Name, err, tt.WantErr)
			}

			var want inventory.Inventory
			if tt.WantPackages != nil {
				want = inventory.Inventory{Packages: tt.WantPackages}
			}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.InputConfig.Path, diff)
			}
		})
	}
}
