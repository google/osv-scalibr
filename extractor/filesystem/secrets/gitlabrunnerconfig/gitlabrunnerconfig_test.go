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

package gitlabrunnerconfig_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/gitlabrunnerconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantScan bool
	}{
		{
			name:     "config_toml_in_gitlab_runner_directory",
			path:     "/etc/gitlab-runner/config.toml",
			wantScan: true,
		},
		{
			name:     "config_toml_with_uppercase",
			path:     "/etc/gitlab-runner/CONFIG.TOML",
			wantScan: true,
		},
		{
			name:     "config_toml_in_nested_gitlab_runner_path",
			path:     "/home/user/.gitlab-runner/config.toml",
			wantScan: true,
		},
		{
			name:     "config_toml_not_in_gitlab_runner_directory",
			path:     "/etc/config.toml",
			wantScan: false,
		},
		{
			name:     "different_filename_in_gitlab_runner_directory",
			path:     "/etc/gitlab-runner/other.toml",
			wantScan: false,
		},
		{
			name:     "config_toml_backup",
			path:     "/etc/gitlab-runner/config.toml.backup",
			wantScan: false,
		},
		{
			name:     "random_file",
			path:     "/home/user/document.txt",
			wantScan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := gitlabrunnerconfig.New(nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			got := e.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.wantScan {
				t.Errorf("FileRequired() = %v, want %v", got, tt.wantScan)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		content         string
		wantSecretFound bool
		wantToken       string
		wantHostname    string
	}{
		{
			name: "valid_config_with_single_runner",
			path: "/etc/gitlab-runner/config.toml",
			content: `concurrent = 1
check_interval = 0

[[runners]]
  name = "test"
  url = "https://gitlab.com"
  token = "glrt-AbCdEfGhIjKlMnOpQrSt"
  executor = "docker"
`,
			wantSecretFound: true,
			wantToken:       "glrt-AbCdEfGhIjKlMnOpQrSt",
			wantHostname:    "gitlab.com",
		},
		{
			name: "valid_config_with_versioned_token",
			path: "/etc/gitlab-runner/config.toml",
			content: `concurrent = 1

[[runners]]
  name = "test"
  url = "https://gitlab.com"
  token = "glrt-0pomZyd4VSw4oyDDd20dU286aQpwOjFiam5mZwp0OjMKsTo5NTBwZRg.01.1j1a9gv3d"
  executor = "ssh"
`,
			wantSecretFound: true,
			wantToken:       "glrt-0pomZyd4VSw4oyDDd20dU286aQpwOjFiam5mZwp0OjMKsTo5NTBwZRg.01.1j1a9gv3d",
			wantHostname:    "gitlab.com",
		},
		{
			name: "self_hosted_gitlab_instance",
			path: "/etc/gitlab-runner/config.toml",
			content: `[[runners]]
  name = "internal"
  url = "https://git.company.internal.com/"
  token = "glrt-InternalToken123456789012345"
  executor = "kubernetes"
`,
			wantSecretFound: true,
			wantToken:       "glrt-InternalToken123456789012345",
			wantHostname:    "git.company.internal.com",
		},
		{
			name: "no_token_in_file",
			path: "/etc/gitlab-runner/config.toml",
			content: `concurrent = 1
check_interval = 0

[[runners]]
  name = "test"
  url = "https://gitlab.com"
  executor = "docker"
`,
			wantSecretFound: false,
		},
		{
			name: "empty_config",
			path: "/etc/gitlab-runner/config.toml",
			content: `concurrent = 1
check_interval = 0
`,
			wantSecretFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := gitlabrunnerconfig.New(nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			r := strings.NewReader(tt.content)
			input := &filesystem.ScanInput{
				Path:   tt.path,
				Reader: io.NopCloser(r),
				Root:   "/",
				FS:     scalibrfs.DirFS("/"),
				Info:   &fakefs.FakeFileInfo{FileName: tt.path},
			}

			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			if !tt.wantSecretFound {
				if len(got.Secrets) != 0 {
					t.Errorf("Extract() found %d secrets, want 0", len(got.Secrets))
				}
				return
			}

			if len(got.Secrets) == 0 {
				t.Errorf("Extract() found no secrets, want at least 1")
				return
			}

			wantInventory := inventory.Inventory{
				Secrets: []*inventory.Secret{
					{
						Location: tt.path,
						Secret: gitlab.RunnerAuthToken{
							Token:    tt.wantToken,
							Hostname: tt.wantHostname,
						},
					},
				},
			}

			if diff := cmp.Diff(wantInventory, got); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNew(t *testing.T) {
	e, err := gitlabrunnerconfig.New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if e.Name() != gitlabrunnerconfig.Name {
		t.Errorf("Name() = %v, want %v", e.Name(), gitlabrunnerconfig.Name)
	}

	if e.Version() != gitlabrunnerconfig.Version {
		t.Errorf("Version() = %v, want %v", e.Version(), gitlabrunnerconfig.Version)
	}
}
