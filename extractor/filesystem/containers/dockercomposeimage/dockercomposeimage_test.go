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
)

func TestFileRequired(t *testing.T) {
	extr := dockercomposeimage.New(dockercomposeimage.DefaultConfig())

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "docker compose file",
			path: "testdata/docker-compose-1.yaml",
			want: true,
		},
		{
			name: "docker compose file with extension",
			path: "testdata/docker-compose-extending.yaml",
			want: true,
		},
		{
			name: "docker compose file extension",
			path: "testdata/docker-compose-yaml-parse-error.yaml",
			want: false,
		},
		{
			name: "not docker compose file",
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
		name         string
		path         string
		cfg          dockercomposeimage.Config
		wantPackages []*extractor.Package
	}{
		{
			name: "single stage docker compose file",
			path: "testdata/docker-compose-extending.yaml",
			cfg:  dockercomposeimage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "ghcr.io/acme/api",
					Version:   "1.2.0",
					Locations: []string{"testdata/docker-compose-extending.yaml"},
					PURLType:  "docker",
				},
				{
					Name:      "ghcr.io/acme/api",
					Version:   "1.3.0-canary",
					Locations: []string{"testdata/docker-compose-extending.yaml"},
					PURLType:  "docker",
				},
				{
					Name:      "ghcr.io/acme/api",
					Version:   "1.3.0-rc",
					Locations: []string{"testdata/docker-compose-extending.yaml"},
					PURLType:  "docker",
				},
			},
		},
		{
			name: "multi stage docker compose file",
			path: "testdata/docker-compose-1.yaml",
			cfg:  dockercomposeimage.DefaultConfig(),
			wantPackages: []*extractor.Package{
				{
					Name:      "nginx",
					Version:   "1.27-alpine",
					Locations: []string{"testdata/docker-compose-1.yaml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "registry-1.docker.io/library/redis",
					Version:   "7.2",
					Locations: []string{"testdata/docker-compose-1.yaml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "ghcr.io/acme/cool-service",
					Version:   "2.3.4",
					Locations: []string{"testdata/docker-compose-1.yaml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp",
					Version:   "2025-09-01",
					Locations: []string{"testdata/docker-compose-1.yaml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "ghcr.io/acme/svc",
					Version:   "1.2.3",
					Locations: []string{"testdata/docker-compose-1.yaml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "ghcr.io/acme/worker",
					Locations: []string{"testdata/docker-compose-1.yaml"},
					PURLType:  purl.TypeDocker,
				},
				{
					Name:      "ghcr.io/acme/worker",
					Version:   "1..0",
					Locations: []string{"testdata/docker-compose-1.yaml"},
					PURLType:  purl.TypeDocker,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr := dockercomposeimage.New(tc.cfg)

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
			name: "invalid docker compose file",
			path: "testdata/docker-compose-yaml-parse-error.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr := dockercomposeimage.New(dockercomposeimage.DefaultConfig())

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
