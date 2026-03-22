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

package argocdimage_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/argocdimage"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		maxFileSizeBytes int64
		wantPackages     []*extractor.Package
	}{
		{
			name: "simple_application",
			path: "testdata/application.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:     "registry-1.docker.io/bitnamicharts/nginx",
					Version:  "1.16.1",
					Location: extractor.LocationFromPath("testdata/application.yaml"),
					PURLType: purl.TypeOCI,
				},
			},
		},
		{
			name: "comprehensive_application_with_multi_source",
			path: "testdata/comprehensive-application.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:     "registry-1.docker.io/bitnamicharts/nginx",
					Version:  "1.16.1",
					Location: extractor.LocationFromPath("testdata/comprehensive-application.yaml"),
					PURLType: purl.TypeOCI,
				},
				{
					Name:     "ghcr.io/my-org/my-chart",
					Version:  "2.0.0",
					Location: extractor.LocationFromPath("testdata/comprehensive-application.yaml"),
					PURLType: purl.TypeOCI,
				},
				{
					Name:     "https://github.com/my-org/my-repo.git/deploy/manifests",
					Version:  "v3.1.0",
					Location: extractor.LocationFromPath("testdata/comprehensive-application.yaml"),
					PURLType: purl.TypeOCI,
				},
			},
		},
		{
			name:             "larger_than_size_limit",
			path:             "testdata/application.yaml",
			maxFileSizeBytes: 1,
			wantPackages:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := argocdimage.New(&cpb.PluginConfig{MaxFileSizeBytes: tc.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("argocdimage.New failed: %v", err)
			}

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			got, err := extr.Extract(context.Background(), &input)
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

func TestFileRequired(t *testing.T) {
	extr, err := argocdimage.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("argocdimage.New failed: %v", err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "yaml_extension",
			path: "application.yaml",
			want: true,
		},
		{
			name: "yml_extension",
			path: "application.yml",
			want: true,
		},
		{
			name: "other_extension",
			path: "config.json",
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

func TestExtract_skip_non_argo_files(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "invalid_YAML_syntax",
			path: "testdata/yaml-parsing-error.yaml",
		},
		{
			name: "non_argo_k8s_resource",
			path: "testdata/not-argo.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := argocdimage.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("argocdimage.New failed: %v", err)
			}

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			inv, err := extr.Extract(context.Background(), &input)
			if err != nil {
				t.Fatalf("Extract(): %v", err)
			}
			if len(inv.Packages) != 0 {
				t.Errorf("Extract(): got %v, want empty packages", inv.Packages)
			}
		})
	}
}
