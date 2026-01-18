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

package dockercomposeimage_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/dockercomposeimage"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	extr, err := dockercomposeimage.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("dockercomposeimage.New failed: %v", err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "compose.yaml",
			path: "testdata/compose.yaml",
			want: true,
		},
		{
			name: "docker_compose_file_with_yml_extension",
			path: "testdata/docker-compose-1.yml",
			want: true,
		},
		{
			name: "docker_compose_file_with_yaml_extension",
			path: "testdata/docker-compose-extending.yaml",
			want: true,
		},
		{
			name: "not_a_docker_compose_file",
			path: "testdata/docker.conf",
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
		name             string
		path             string
		maxFileSizeBytes int64
		wantPackages     []*extractor.Package
	}{
		{
			name: "single_stage_docker_compose_file",
			path: "testdata/docker-compose-extending.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:      "ghcr.io/acme/api",
					Version:   "1.2.0",
					Locations: []string{"testdata/docker-compose-extending.yaml"},
					PURLType:  "docker",
				},
			},
		},
		{
			name: "multi_stage_docker_compose_file",
			path: "testdata/docker-compose-1.yml",
			wantPackages: []*extractor.Package{
				// "image3" and "image6" are not expected because
				// the version values are set(partially) via environment variables,
				// the responsible environment variable values are not known at extraction time,
				// and the version values are imperfectly extracted.
				{
					Name:      "image1",
					Version:   "1.1.1",
					Locations: []string{"testdata/docker-compose-1.yml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "image2",
					Version:   "2.2.2",
					Locations: []string{"testdata/docker-compose-1.yml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "image4",
					Version:   "4.4.4",
					Locations: []string{"testdata/docker-compose-1.yml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "image5",
					Version:   "5.5.5",
					Locations: []string{"testdata/docker-compose-1.yml"},
					PURLType:  purl.TypeDocker,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := dockercomposeimage.New(&cpb.PluginConfig{MaxFileSizeBytes: tc.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("dockercomposeimage.New failed: %v", err)
			}

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
			name: "invalid_docker_compose_file",
			path: "testdata/docker-compose-yaml-parse-error.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := dockercomposeimage.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("dockercomposeimage.New failed: %v", err)
			}

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			got, _ := extr.Extract(t.Context(), &input)
			if diff := cmp.Diff(inventory.Inventory{}, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tc.path, diff)
			}
		})
	}
}
