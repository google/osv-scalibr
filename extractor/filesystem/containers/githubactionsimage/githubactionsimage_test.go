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

package githubactionsimage_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/githubactionsimage"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestNew(t *testing.T) {
	extr, err := githubactionsimage.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr == nil {
		t.Fatal("New() returned nil extractor")
	}
}

func TestName(t *testing.T) {
	extr, err := githubactionsimage.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr.Name() != "containers/githubactionsimage" {
		t.Errorf("Name() = %q, want %q", extr.Name(), "containers/githubactionsimage")
	}
}

func TestVersion(t *testing.T) {
	extr, err := githubactionsimage.New(&cpb.PluginConfig{})
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
			name: "workflow_file_yml_at_repo_root",
			path: ".github/workflows/ci.yml",
			want: true,
		},
		{
			name: "workflow_file_yaml_at_repo_root",
			path: ".github/workflows/release.yaml",
			want: true,
		},
		{
			name: "workflow_file_inside_subdirectory_repo",
			path: "src/myrepo/.github/workflows/build.yml",
			want: true,
		},
		{
			name: "absolute_style_path_with_workflows",
			path: "home/user/proj/.github/workflows/test.yml",
			want: true,
		},
		{
			name: "yml_under_workflows_subdir_should_not_match",
			path: ".github/workflows/sub/build.yml",
			want: false,
		},
		{
			name: "yml_under_dot_github_but_not_workflows",
			path: ".github/dependabot.yml",
			want: false,
		},
		{
			name: "yml_under_workflows_but_not_dot_github",
			path: "workflows/build.yml",
			want: false,
		},
		{
			name: "non_yaml_extension_under_workflows",
			path: ".github/workflows/notes.txt",
			want: false,
		},
		{
			name: "unrelated_yaml_file",
			path: "config/app.yml",
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := githubactionsimage.New(&cpb.PluginConfig{})
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
	extr, err := githubactionsimage.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	path := ".github/workflows/big.yml"
	fi := fakefs.FakeFileInfo{FileName: path, FileSize: 200}
	if extr.FileRequired(simplefileapi.New(path, fi)) {
		t.Errorf("FileRequired(%q) = true, want false (over size limit)", path)
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantPackages []*extractor.Package
	}{
		{
			name: "job_with_container_image",
			path: "testdata/workflow-container.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:     "node",
					Version:  "14.16",
					Location: extractor.LocationFromPath("testdata/workflow-container.yaml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "job_with_service_images",
			path: "testdata/workflow-services.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:     "postgres",
					Version:  "15",
					Location: extractor.LocationFromPath("testdata/workflow-services.yaml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "redis",
					Version:  "7.0",
					Location: extractor.LocationFromPath("testdata/workflow-services.yaml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "mixed_container_and_services",
			path: "testdata/workflow-mixed.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/workflow-mixed.yaml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "mysql",
					Version:  "8.0",
					Location: extractor.LocationFromPath("testdata/workflow-mixed.yaml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:         "no_images",
			path:         "testdata/workflow-empty.yaml",
			wantPackages: nil,
		},
		{
			name:         "invalid_yaml",
			path:         "testdata/workflow-invalid.yaml",
			wantPackages: nil,
		},
		{
			name:         "variables_skipped",
			path:         "testdata/workflow-variables.yaml",
			wantPackages: nil,
		},
		{
			name: "port_in_registry",
			path: "testdata/workflow-port.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:     "registry.example.com:5000/my-image",
					Version:  "latest",
					Location: extractor.LocationFromPath("testdata/workflow-port.yaml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := githubactionsimage.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("githubactionsimage.New failed: %v", err)
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
