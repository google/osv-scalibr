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

package drone_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/drone"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestNew(t *testing.T) {
	extr, err := drone.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr == nil {
		t.Fatal("New() returned nil extractor")
	}
}

func TestName(t *testing.T) {
	extr, err := drone.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr.Name() != "containers/drone" {
		t.Errorf("Name() = %q, want %q", extr.Name(), "containers/drone")
	}
}

func TestVersion(t *testing.T) {
	extr, err := drone.New(&cpb.PluginConfig{})
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
			name: "drone_yml_at_repo_root",
			path: ".drone.yml",
			want: true,
		},
		{
			name: "drone_yaml_at_repo_root",
			path: ".drone.yaml",
			want: true,
		},
		{
			name: "drone_yml_in_subdirectory",
			path: "project/.drone.yml",
			want: true,
		},
		{
			name: "drone_yaml_in_subdirectory",
			path: "project/.drone.yaml",
			want: true,
		},
		{
			name: "other_yaml_not_required",
			path: "other.yaml",
			want: false,
		},
		{
			name: "other_yml_not_required",
			path: "other.yml",
			want: false,
		},
		{
			name: "non_yaml_not_required",
			path: ".drone.txt",
			want: false,
		},
		{
			name: "similar_name_not_required",
			path: "my.drone.yml",
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := drone.New(&cpb.PluginConfig{})
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
	extr, err := drone.New(&cpb.PluginConfig{MaxFileSizeBytes: 1})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	path := ".drone.yml"
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
			name: "comprehensive_steps_and_services",
			path: "testdata/.drone.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/.drone.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "node",
					Version:  "20",
					Location: extractor.LocationFromPath("testdata/.drone.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "redis",
					Version:  "7.0",
					Location: extractor.LocationFromPath("testdata/.drone.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "postgres",
					Version:  "15",
					Location: extractor.LocationFromPath("testdata/.drone.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "digest_format",
			path: "testdata/.drone-digest.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "gcr.io/project-id/my-image",
					Version:  "sha256:abc123def456",
					Location: extractor.LocationFromPath("testdata/.drone-digest.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "duplicates_deduplicated",
			path: "testdata/.drone-duplicates.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "ubuntu",
					Version:  "latest",
					Location: extractor.LocationFromPath("testdata/.drone-duplicates.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:         "empty_drone",
			path:         "testdata/.drone-empty.yml",
			wantPackages: nil,
		},
		{
			name:         "invalid_yaml",
			path:         "testdata/.drone-invalid.yml",
			wantPackages: nil,
		},
		{
			name: "port_in_registry",
			path: "testdata/.drone-port.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "registry.example.com:5000/my-image",
					Version:  "latest",
					Location: extractor.LocationFromPath("testdata/.drone-port.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "services_only",
			path: "testdata/.drone-services-only.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "redis",
					Version:  "7.0",
					Location: extractor.LocationFromPath("testdata/.drone-services-only.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "postgres",
					Version:  "15",
					Location: extractor.LocationFromPath("testdata/.drone-services-only.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "steps_only",
			path: "testdata/.drone-steps-only.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/.drone-steps-only.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "node",
					Version:  "20",
					Location: extractor.LocationFromPath("testdata/.drone-steps-only.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "multiple_services",
			path: "testdata/.drone-multiple-services.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "redis",
					Version:  "7.0",
					Location: extractor.LocationFromPath("testdata/.drone-multiple-services.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "postgres",
					Version:  "15",
					Location: extractor.LocationFromPath("testdata/.drone-multiple-services.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "mysql",
					Version:  "8.0",
					Location: extractor.LocationFromPath("testdata/.drone-multiple-services.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "mongo",
					Version:  "6.0",
					Location: extractor.LocationFromPath("testdata/.drone-multiple-services.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:             "larger_than_size_limit",
			path:             "testdata/.drone.yml",
			maxFileSizeBytes: 1,
			wantPackages:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := drone.New(&cpb.PluginConfig{MaxFileSizeBytes: tc.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("drone.New failed: %v", err)
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
