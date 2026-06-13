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

package circleci_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/circleci"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestNew(t *testing.T) {
	extr, err := circleci.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr == nil {
		t.Fatal("New() returned nil extractor")
	}
}

func TestName(t *testing.T) {
	extr, err := circleci.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr.Name() != "containers/circleci" {
		t.Errorf("Name() = %q, want %q", extr.Name(), "containers/circleci")
	}
}

func TestVersion(t *testing.T) {
	extr, err := circleci.New(&cpb.PluginConfig{})
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
			name: "config_yml_at_repo_root",
			path: ".circleci/config.yml",
			want: true,
		},
		{
			name: "config_yaml_at_repo_root",
			path: ".circleci/config.yaml",
			want: true,
		},
		{
			name: "config_yml_inside_subdirectory",
			path: "project/.circleci/config.yml",
			want: true,
		},
		{
			name: "config_yaml_inside_subdirectory",
			path: "project/.circleci/config.yaml",
			want: true,
		},
		{
			name: "config_yml_under_circleci_subdir_should_not_match",
			path: ".circleci/sub/config.yml",
			want: false,
		},
		{
			name: "yml_under_circleci_but_not_named_config",
			path: ".circleci/other.yml",
			want: false,
		},
		{
			name: "txt_under_circleci",
			path: ".circleci/config.txt",
			want: false,
		},
		{
			name: "unrelated_yaml_file",
			path: "config/app.yml",
			want: false,
		},
		{
			name: "config_yml_without_circleci_dir",
			path: "config.yml",
			want: false,
		},
		{
			name: "mixed_case_CONFIG_YML",
			path: ".circleci/CONFIG.YML",
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := circleci.New(&cpb.PluginConfig{})
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
	extr, err := circleci.New(&cpb.PluginConfig{MaxFileSizeBytes: 1})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	path := ".circleci/config.yml"
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
			name: "comprehensive_multi_image_test_file",
			path: "testdata/config.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/config.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "redis",
					Version:  "7.0",
					Location: extractor.LocationFromPath("testdata/config.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "cimg/node",
					Version:  "20.0",
					Location: extractor.LocationFromPath("testdata/config.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "postgres",
					Version:  "15",
					Location: extractor.LocationFromPath("testdata/config.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "cimg/python",
					Version:  "3.11",
					Location: extractor.LocationFromPath("testdata/config.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "digest_format",
			path: "testdata/config-digest.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "gcr.io/project-id/my-image",
					Version:  "sha256:abc123def456",
					Location: extractor.LocationFromPath("testdata/config-digest.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "variables_skipped",
			path: "testdata/config-variables.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "ubuntu",
					Version:  "latest",
					Location: extractor.LocationFromPath("testdata/config-variables.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "duplicates_deduplicated",
			path: "testdata/config-duplicates.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "ubuntu",
					Version:  "latest",
					Location: extractor.LocationFromPath("testdata/config-duplicates.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:         "empty_config",
			path:         "testdata/config-empty.yml",
			wantPackages: nil,
		},
		{
			name:         "invalid_yaml",
			path:         "testdata/config-invalid.yml",
			wantPackages: nil,
		},
		{
			name: "port_in_registry",
			path: "testdata/config-port.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "registry.example.com:5000/my-image",
					Version:  "latest",
					Location: extractor.LocationFromPath("testdata/config-port.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "executor_only",
			path: "testdata/config-executor-only.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/config-executor-only.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "jobs_only",
			path: "testdata/config-jobs-only.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "node",
					Version:  "20",
					Location: extractor.LocationFromPath("testdata/config-jobs-only.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "multiple_docker_images_per_job",
			path: "testdata/config-multiple-docker.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "cimg/node",
					Version:  "20.0",
					Location: extractor.LocationFromPath("testdata/config-multiple-docker.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "postgres",
					Version:  "15",
					Location: extractor.LocationFromPath("testdata/config-multiple-docker.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "redis",
					Version:  "7",
					Location: extractor.LocationFromPath("testdata/config-multiple-docker.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:             "larger_than_size_limit",
			path:             "testdata/config.yml",
			maxFileSizeBytes: 1,
			wantPackages:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := circleci.New(&cpb.PluginConfig{MaxFileSizeBytes: tc.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("circleci.New failed: %v", err)
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
