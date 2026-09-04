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

package gitlab

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseRepoURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    *RepoInfo
		wantNil bool
	}{
		{
			name:   "HTTPS_URL_with_single_group",
			rawURL: "https://gitlab.com/mygroup/myproject.git",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "gitlab.com",
				Namespace: "mygroup",
				Project:   "myproject",
				FullPath:  "mygroup/myproject",
			},
		},
		{
			name:   "HTTPS_URL_with_nested_subgroups",
			rawURL: "https://gitlab.com/org/backend/api-service.git",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "gitlab.com",
				Namespace: "org/backend",
				Project:   "api-service",
				FullPath:  "org/backend/api-service",
			},
		},
		{
			name:   "HTTPS_URL_with_deeply_nested_subgroups",
			rawURL: "https://gitlab.com/company/division/team/backend/services/api.git",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "gitlab.com",
				Namespace: "company/division/team/backend/services",
				Project:   "api",
				FullPath:  "company/division/team/backend/services/api",
			},
		},
		{
			name:   "HTTP_URL_non_secure",
			rawURL: "http://gitlab.example.com/group/project.git",
			want: &RepoInfo{
				Scheme:    "http",
				Host:      "gitlab.example.com",
				Namespace: "group",
				Project:   "project",
				FullPath:  "group/project",
			},
		},
		{
			name:   "SSH_scp_style_URL",
			rawURL: "git@gitlab.com:mygroup/myproject.git",
			want: &RepoInfo{
				Scheme:    "git",
				Host:      "gitlab.com",
				Namespace: "mygroup",
				Project:   "myproject",
				FullPath:  "mygroup/myproject",
			},
		},
		{
			name:   "SSH_scp_style_URL_with_nested_subgroups",
			rawURL: "git@gitlab.com:org/backend/api-service.git",
			want: &RepoInfo{
				Scheme:    "git",
				Host:      "gitlab.com",
				Namespace: "org/backend",
				Project:   "api-service",
				FullPath:  "org/backend/api-service",
			},
		},
		{
			name:   "SSH_URL_style_format",
			rawURL: "ssh://git@gitlab.com/group/project.git",
			want: &RepoInfo{
				Scheme:    "ssh",
				Host:      "gitlab.com",
				Namespace: "group",
				Project:   "project",
				FullPath:  "group/project",
			},
		},
		{
			name:   "SSH_URL_style_with_nested_subgroups",
			rawURL: "ssh://git@gitlab.example.com/org/team/backend/service.git",
			want: &RepoInfo{
				Scheme:    "ssh",
				Host:      "gitlab.example.com",
				Namespace: "org/team/backend",
				Project:   "service",
				FullPath:  "org/team/backend/service",
			},
		},
		{
			name:   "Self_hosted_GitLab_instance",
			rawURL: "https://git.company.internal/engineering/backend.git",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "git.company.internal",
				Namespace: "engineering",
				Project:   "backend",
				FullPath:  "engineering/backend",
			},
		},
		{
			name:   "Self_hosted_with_subdomain",
			rawURL: "https://gitlab.dev.example.com/team/project.git",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "gitlab.dev.example.com",
				Namespace: "team",
				Project:   "project",
				FullPath:  "team/project",
			},
		},
		{
			name:   "SSH_scp_style_with_self_hosted",
			rawURL: "git@git.internal:org/project.git",
			want: &RepoInfo{
				Scheme:    "git",
				Host:      "git.internal",
				Namespace: "org",
				Project:   "project",
				FullPath:  "org/project",
			},
		},
		{
			name:    "Invalid_missing_project_only_one_segment",
			rawURL:  "https://gitlab.com/onlyone.git",
			wantNil: true,
		},
		{
			name:    "Invalid_no_path_segments",
			rawURL:  "https://gitlab.com/.git",
			wantNil: true,
		},
		{
			name:    "Invalid_SSH_format_without_colon",
			rawURL:  "git@gitlab.com/group/project.git",
			wantNil: true,
		},
		{
			name:    "Invalid_malformed_URL",
			rawURL:  "not-a-url",
			wantNil: true,
		},
		{
			name:    "Invalid_empty_string",
			rawURL:  "",
			wantNil: true,
		},
		{
			name:   "URL_without_git_suffix",
			rawURL: "https://gitlab.com/mygroup/myproject",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "gitlab.com",
				Namespace: "mygroup",
				Project:   "myproject",
				FullPath:  "mygroup/myproject",
			},
		},
		{
			name:   "URL_with_port_number",
			rawURL: "https://gitlab.example.com:8443/group/project.git",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "gitlab.example.com:8443",
				Namespace: "group",
				Project:   "project",
				FullPath:  "group/project",
			},
		},
		{
			name:   "SSH_scp_style_with_port",
			rawURL: "git@gitlab.example.com:2222:group/project.git",
			want: &RepoInfo{
				Scheme:    "git",
				Host:      "gitlab.example.com",
				Namespace: "2222:group",
				Project:   "project",
				FullPath:  "2222:group/project",
			},
		},
		{
			name:   "URL_with_hyphens_and_underscores_in_path",
			rawURL: "https://gitlab.com/my-org/my_project-v2.git",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "gitlab.com",
				Namespace: "my-org",
				Project:   "my_project-v2",
				FullPath:  "my-org/my_project-v2",
			},
		},
		{
			name:   "URL_with_dots_in_path",
			rawURL: "https://gitlab.com/org.name/project.name.git",
			want: &RepoInfo{
				Scheme:    "https",
				Host:      "gitlab.com",
				Namespace: "org.name",
				Project:   "project.name",
				FullPath:  "org.name/project.name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseRepoURL(tt.rawURL)
			if tt.wantNil {
				if got != nil {
					t.Errorf("ParseRepoURL() = %+v, want nil", got)
				}
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseRepoURL() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
