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

package dockerbaseimage_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/dockerbaseimage"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	extr := dockerbaseimage.New(dockerbaseimage.DefaultConfig())

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "Dockerfile",
			path: "testdata/Dockerfile",
			want: true,
		},
		{
			name: "mixed-case_Dockerfile",
			path: "testdata/dOcKeRfile",
			want: true,
		},
		{
			name: "Dockerfile_with_extension",
			path: "testdata/Dockerfile.prod",
			want: true,
		},
		{
			name: "Dockerfile_extension",
			path: "testdata/ext.dockerfile",
			want: true,
		},
		{
			name: "not_Dockerfile",
			path: "testdata/pip.conf",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isRequired := extr.FileRequired(simplefileapi.New(tc.path, nil))
			if isRequired != tc.want {
				t.Fatalf("FileRequired(%s): got %v, want %v", tc.path, isRequired, tc.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		cfg          dockerbaseimage.Config
		wantPackages []*extractor.Package
	}{
		{
			name: "single_stage_dockerfile",
			path: "testdata/dockerfile.single-stage",
			cfg:  dockerbaseimage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "nginx",
					Version:   "1.27.4",
					Locations: []string{"testdata/dockerfile.single-stage"},
					PURLType:  purl.TypeDocker,
				},
			},
		},
		{
			name: "multi_stage_dockerfile",
			path: "testdata/dockerfile.multi-stage",
			cfg:  dockerbaseimage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "nginx",
					Version:   "1.27.4",
					Locations: []string{"testdata/dockerfile.multi-stage"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "ubuntu",
					Version:   "latest",
					Locations: []string{"testdata/dockerfile.multi-stage"},
					PURLType:  purl.TypeDocker,
				},
			},
		},
		{
			name: "parameterized_dockerfile",
			path: "testdata/dockerfile.parameterized",
			cfg:  dockerbaseimage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "nginx",
					Version:   "1.27.4",
					Locations: []string{"testdata/dockerfile.parameterized"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "ubuntu",
					Version:   "latest",
					Locations: []string{"testdata/dockerfile.parameterized"},
					PURLType:  purl.TypeDocker,
				},
			},
		},
		{
			name: "versionless_dockerfile",
			path: "testdata/dockerfile.no-version",
			cfg:  dockerbaseimage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "nginx",
					Version:   "latest",
					Locations: []string{"testdata/dockerfile.no-version"},
					PURLType:  purl.TypeDocker,
				},
			},
		},
		{
			name: "sha256_version",
			path: "testdata/dockerfile.hash",
			cfg:  dockerbaseimage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "nginx",
					Version:   "sha256:5a271780516b718910041c0993952f14371490216692290d234a9b231d102e1c",
					Locations: []string{"testdata/dockerfile.hash"},
					PURLType:  purl.TypeDocker,
				},
			},
		},
		{
			name:         "scratch layer",
			path:         "testdata/dockerfile.scratch",
			cfg:          dockerbaseimage.DefaultConfig(),
			wantPackages: nil,
		},
		{
			name:         "larger than size limit",
			path:         "testdata/dockerfile.multi-stage",
			cfg:          dockerbaseimage.Config{MaxFileSizeBytes: 1},
			wantPackages: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr := dockerbaseimage.New(tc.cfg)

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			got, err := extr.Extract(t.Context(), &input)
			if err != nil {
				t.Fatalf("%s.Extract(%q) failed: %v", extr.Name(), tc.path, err)
			}

			wantInv := inventory.Inventory{Packages: tc.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tc.path, diff)
			}
		})
	}
}

func TestExtract_failures(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "invalid_Dockerfile",
			path: "testdata/dockerfile.invalid",
		},
		{
			name: "empty_Dockerfile",
			path: "testdata/dockerfile.empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr := dockerbaseimage.New(dockerbaseimage.DefaultConfig())

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			_, err := extr.Extract(t.Context(), &input)
			if err == nil {
				t.Fatalf("Extract(): got nil, want err")
			}
		})
	}
}
