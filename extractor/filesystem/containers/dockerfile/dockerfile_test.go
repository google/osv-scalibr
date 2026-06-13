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

package dockerfile_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/dockerfile"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestNew(t *testing.T) {
	extr, err := dockerfile.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr == nil {
		t.Fatal("New() returned nil extractor")
	}
}

func TestName(t *testing.T) {
	extr, err := dockerfile.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr.Name() != "containers/dockerfile" {
		t.Errorf("Name() = %q, want %q", extr.Name(), "containers/dockerfile")
	}
}

func TestVersion(t *testing.T) {
	extr, err := dockerfile.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr.Version() != 0 {
		t.Errorf("Version() = %d, want 0", extr.Version())
	}
}

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "dockerfile_at_repo_root",
			path: "Dockerfile",
			want: true,
		},
		{
			name: "dockerfile_lowercase",
			path: "dockerfile",
			want: true,
		},
		{
			name: "dockerfile_with_suffix",
			path: "Dockerfile.prod",
			want: true,
		},
		{
			name: "dockerfile_with_suffix_lowercase",
			path: "dockerfile.dev",
			want: true,
		},
		{
			name: "named_dockerfile",
			path: "app.dockerfile",
			want: true,
		},
		{
			name: "named_dockerfile_uppercase",
			path: "app.Dockerfile",
			want: true,
		},
		{
			name: "dockerfile_in_subdirectory",
			path: "project/Dockerfile",
			want: true,
		},
		{
			name: "other_file_not_required",
			path: "other.txt",
			want: false,
		},
		{
			name: "yaml_file_also_required",
			path: "Dockerfile.yaml",
			want: true,
		},
		{
			name: "similar_name_not_required",
			path: "my-Dockerfile",
			want: false,
		},
		{
			name: "dockerfile_extension_in_middle_not_required",
			path: "dockerfile.txt",
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := dockerfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}
			fi := fakefs.FakeFileInfo{FileName: tc.path, FileSize: 1024}
			got := extr.FileRequired(simplefileapi.New(tc.path, fi))
			if got != tc.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestFileRequired_FileSizeLimit(t *testing.T) {
	extr, err := dockerfile.New(&cpb.PluginConfig{MaxFileSizeBytes: 1})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	path := "Dockerfile"
	fi := fakefs.FakeFileInfo{FileName: path, FileSize: 1024}
	if extr.FileRequired(simplefileapi.New(path, fi)) {
		t.Errorf("FileRequired(%q) = true, want false (over size limit)", path)
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
			name: "comprehensive_multi_stage",
			path: "testdata/Dockerfile",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/Dockerfile"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "node",
					Version:  "20",
					Location: extractor.LocationFromPath("testdata/Dockerfile"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "nginx",
					Version:  "1.25",
					Location: extractor.LocationFromPath("testdata/Dockerfile"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "digest_format",
			path: "testdata/Dockerfile-digest",
			wantPackages: []*extractor.Package{
				{
					Name:     "alpine",
					Version:  "sha256:abc123def456",
					Location: extractor.LocationFromPath("testdata/Dockerfile-digest"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:         "variables_skipped",
			path:         "testdata/Dockerfile-variables",
			wantPackages: nil,
		},
		{
			name: "duplicates_deduplicated",
			path: "testdata/Dockerfile-duplicates",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/Dockerfile-duplicates"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:         "empty_dockerfile",
			path:         "testdata/Dockerfile-empty",
			wantPackages: nil,
		},
		{
			name:         "invalid_syntax",
			path:         "testdata/Dockerfile-invalid",
			wantPackages: nil,
		},
		{
			name: "port_in_registry",
			path: "testdata/Dockerfile-port",
			wantPackages: []*extractor.Package{
				{
					Name:     "registry.example.com:5000/my-image",
					Version:  "tag",
					Location: extractor.LocationFromPath("testdata/Dockerfile-port"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "as_stage_syntax",
			path: "testdata/Dockerfile-as",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/Dockerfile-as"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "platform_flag_skipped",
			path: "testdata/Dockerfile-platform",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/Dockerfile-platform"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "scratch_image",
			path: "testdata/Dockerfile-scratch",
			wantPackages: []*extractor.Package{
				{
					Name:     "scratch",
					Version:  "latest",
					Location: extractor.LocationFromPath("testdata/Dockerfile-scratch"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "commented_lines",
			path: "testdata/Dockerfile-commented",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/Dockerfile-commented"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "alpine",
					Version:  "latest",
					Location: extractor.LocationFromPath("testdata/Dockerfile-commented"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "lowercase_from",
			path: "testdata/Dockerfile-lowercase",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/Dockerfile-lowercase"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:             "larger_than_size_limit",
			path:             "testdata/Dockerfile",
			maxFileSizeBytes: 1,
			wantPackages:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := dockerfile.New(&cpb.PluginConfig{MaxFileSizeBytes: tc.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("dockerfile.New failed: %v", err)
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
				t.Errorf("Extract() returned unexpected inventory (-want +got):\n%s", diff)
			}
		})
	}
}
