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

package k8simage_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/k8simage"
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
			name: "comprehensive_multi-resource_test_file",
			path: "testdata/comprehensive-test.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:      "tag1",
					Version:   "sha256:b692a91e4e531d2a9cd8e8c3b1e6d5c7f9d2e5a3b1c8d7f4e6a9b2c5d8f1e4a7",
					Locations: []string{"testdata/comprehensive-test.yaml"},
					PURLType:  purl.TypeK8s,
				},
				{
					Name:      "tag2",
					Version:   "2.0.0",
					Locations: []string{"testdata/comprehensive-test.yaml"},
					PURLType:  purl.TypeK8s,
				},
				{
					Name:      "tag3",
					Version:   "3.0.0",
					Locations: []string{"testdata/comprehensive-test.yaml"},
					PURLType:  purl.TypeK8s,
				},
				{
					Name:      "tag4.io/prometheus/node-exporter",
					Version:   "v4.0.0",
					Locations: []string{"testdata/comprehensive-test.yaml"},
					PURLType:  purl.TypeK8s,
				},
				{
					Name:      "tag5",
					Version:   "5.0.0",
					Locations: []string{"testdata/comprehensive-test.yaml"},
					PURLType:  purl.TypeK8s,
				},
				{
					Name:      "tag6",
					Version:   "6.0.0",
					Locations: []string{"testdata/comprehensive-test.yaml"},
					PURLType:  purl.TypeK8s,
				},
				{
					Name:      "tag7:5000/my-app",
					Version:   "dev",
					Locations: []string{"testdata/comprehensive-test.yaml"},
					PURLType:  purl.TypeK8s,
				},
				{
					Name:      "centos",
					Version:   "latest",
					Locations: []string{"testdata/comprehensive-test.yaml"},
					PURLType:  purl.TypeK8s,
				},
			},
		},
		{
			name:             "larger than size limit",
			path:             "testdata/comprehensive-test.yaml",
			maxFileSizeBytes: 1,
			wantPackages:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := k8simage.New(&cpb.PluginConfig{MaxFileSizeBytes: tc.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("k8simage.New failed: %v", err)
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
	extr, err := k8simage.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("k8simage.New failed: %v", err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "yaml_extension",
			path: "deployment.yaml",
			want: true,
		},
		{
			name: "yml_extension",
			path: "service.yml",
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

func TestExtract_empty_results(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "empty_image_fields_should_result_in_no_packages",
			path: "testdata/comprehensive-test-failures.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := k8simage.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("k8simage.New failed: %v", err)
			}

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			got, err := extr.Extract(context.Background(), &input)
			if err != nil {
				t.Fatalf("%s.Extract(%q) failed: %v", extr.Name(), tc.path, err)
			}

			// Should have no packages since all image fields are empty or with errors
			if len(got.Packages) != 0 {
				t.Errorf("%s.Extract(%q): got %d packages, want 0. Packages: %+v",
					extr.Name(), tc.path, len(got.Packages), got.Packages)
			}
		})
	}
}

func TestExtract_skip_non_k8s_files(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "invalid_YAML_syntax",
			path: "testdata/yaml-parsing-error.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := k8simage.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("k8simage.New failed: %v", err)
			}

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			inventory, err := extr.Extract(context.Background(), &input)
			if err != nil {
				t.Fatalf("Extract(): %v", err)
			}
			if len(inventory.Packages) != 0 {
				t.Errorf("Extract(): got %v, want empty package", inventory.Packages)
			}
		})
	}
}
