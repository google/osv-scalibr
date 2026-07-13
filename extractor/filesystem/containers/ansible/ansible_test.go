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

package ansible_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/ansible"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestNew(t *testing.T) {
	extr, err := ansible.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr == nil {
		t.Fatal("New() returned nil extractor")
	}
}

func TestName(t *testing.T) {
	extr, err := ansible.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if extr.Name() != "containers/ansible" {
		t.Errorf("Name() = %q, want %q", extr.Name(), "containers/ansible")
	}
}

func TestVersion(t *testing.T) {
	extr, err := ansible.New(&cpb.PluginConfig{})
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
		{"playbook_yml", "playbook.yml", true},
		{"playbook_yaml", "playbook.yaml", true},
		{"site_yml", "site.yml", true},
		{"site_yaml", "site.yaml", true},
		{"deploy_yml", "deploy.yml", true},
		{"deploy_yaml", "deploy.yaml", true},
		{"main_yml", "main.yml", true},
		{"main_yaml", "main.yaml", true},
		{"setup_yml", "setup.yml", true},
		{"setup_yaml", "setup.yaml", true},
		{"install_yml", "install.yml", true},
		{"install_yaml", "install.yaml", true},
		{"playbook_suffix", "my-playbook.yml", true},
		{"playbook_prefix", "playbook-deploy.yml", true},
		{"playbook_uppercase", "PLAYBOOK.YML", true},
		{"sub_playbook", "ansible/playbook.yml", true},
		{"readme_txt", "readme.txt", false},
		{"config_yml", "config.yml", false},
		{"playbook_json", "playbook.json", false},
		{"playbook_no_ext", "playbook", false},
		{"tasks_main_yml", "roles/common/tasks/main.yml", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := ansible.New(&cpb.PluginConfig{})
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
	extr, err := ansible.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	path := "playbook.yml"
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
			name: "docker_container_tasks",
			path: "testdata/playbook.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "nginx",
					Version:  "1.25",
					Location: extractor.LocationFromPath("testdata/playbook.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "redis",
					Version:  "7.0",
					Location: extractor.LocationFromPath("testdata/playbook.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "digest_format",
			path: "testdata/playbook-digest.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "nginx",
					Version:  "sha256:abc123",
					Location: extractor.LocationFromPath("testdata/playbook-digest.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "community_docker_module",
			path: "testdata/playbook-community.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "postgres",
					Version:  "15",
					Location: extractor.LocationFromPath("testdata/playbook-community.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "duplicates_deduped",
			path: "testdata/playbook-duplicates.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "nginx",
					Version:  "1.25",
					Location: extractor.LocationFromPath("testdata/playbook-duplicates.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:         "no_docker_container",
			path:         "testdata/playbook-empty.yml",
			wantPackages: nil,
		},
		{
			name:         "invalid_yaml",
			path:         "testdata/playbook-invalid.yml",
			wantPackages: nil,
		},
		{
			name: "registry_with_port",
			path: "testdata/playbook-port.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "registry.example.com:5000/my-image",
					Version:  "tag",
					Location: extractor.LocationFromPath("testdata/playbook-port.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:         "jinja2_variables_skipped",
			path:         "testdata/playbook-variables.yml",
			wantPackages: nil,
		},
		{
			name: "handlers_section",
			path: "testdata/playbook-handlers.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "nginx",
					Version:  "1.25",
					Location: extractor.LocationFromPath("testdata/playbook-handlers.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "redis",
					Version:  "7.0",
					Location: extractor.LocationFromPath("testdata/playbook-handlers.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "roles_tasks",
			path: "testdata/playbook-roles.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.21",
					Location: extractor.LocationFromPath("testdata/playbook-roles.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name: "pre_tasks_and_post_tasks",
			path: "testdata/playbook-pre-post.yml",
			wantPackages: []*extractor.Package{
				{
					Name:     "alpine",
					Version:  "3.18",
					Location: extractor.LocationFromPath("testdata/playbook-pre-post.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "ubuntu",
					Version:  "22.04",
					Location: extractor.LocationFromPath("testdata/playbook-pre-post.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
		{
			name:         "name_only_no_image",
			path:         "testdata/playbook-name-only.yml",
			wantPackages: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := ansible.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("ansible.New failed: %v", err)
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
