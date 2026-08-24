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

package gitrepo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{name: "git directory", inputPath: "/foo/bar/.git", want: true},
		{name: "git directory trailing slash", inputPath: "/foo/bar/.git/", want: true},
		{name: "not git", inputPath: "/foo/bar/baz", want: false},
		{name: "git config file", inputPath: "/foo/bar/.git/config", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestDirExtractor_Extract(t *testing.T) {
	commitSHA := "1234567890abcdef1234567890abcdef12345678"
	packedSHA := "abcdef1234567890abcdef1234567890abcdef12"
	configContent := `
[core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = https://github.com/google/repo-foo.git
`
	packedRefsContent := "# packed-refs with comments\n" +
		"fedcba9876543210fedcba9876543210fedcba98 refs/heads/other\n" +
		packedSHA + " refs/heads/packed\n"

	tests := []struct {
		name         string
		path         string
		setupSubtest func(t *testing.T, dotGit string)
		wantPackages []*extractor.Package
		wantErr      bool
	}{
		{
			name: "Standard repo with loose ref",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
					t.Fatalf("Failed to write HEAD: %v", err)
				}
				if err := os.MkdirAll(filepath.Join(dotGit, "refs", "heads"), 0755); err != nil {
					t.Fatalf("Failed to create refs dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dotGit, "refs", "heads", "main"), []byte(commitSHA+"\n"), 0644); err != nil {
					t.Fatalf("Failed to write ref file: %v", err)
				}
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					Version:  commitSHA,
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: commitSHA,
					},
				},
			},
		},
		{
			name: "Standard repo with packed ref",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/packed\n"), 0644); err != nil {
					t.Fatalf("Failed to write HEAD: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dotGit, "packed-refs"), []byte(packedRefsContent), 0644); err != nil {
					t.Fatalf("Failed to write packed-refs: %v", err)
				}
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					Version:  packedSHA,
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: packedSHA,
					},
				},
			},
		},
		{
			name: "Standard repo with packed-refs containing comments, peeling and empty lines",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/packed\n"), 0644); err != nil {
					t.Fatalf("Failed to write HEAD: %v", err)
				}
				content := "# refs/heads/packed\n" +
					"\n" +
					"^ refs/heads/packed\n" +
					packedSHA + " refs/heads/packed\n"
				if err := os.WriteFile(filepath.Join(dotGit, "packed-refs"), []byte(content), 0644); err != nil {
					t.Fatalf("Failed to write packed-refs: %v", err)
				}
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					Version:  packedSHA,
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: packedSHA,
					},
				},
			},
		},
		{
			name: "Standard repo with packed-refs containing invalid ref line with no space",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/packed\n"), 0644); err != nil {
					t.Fatalf("Failed to write HEAD: %v", err)
				}
				content := "# refs/heads/packed\n" +
					"invalidline\n" +
					packedSHA + " refs/heads/packed\n"
				if err := os.WriteFile(filepath.Join(dotGit, "packed-refs"), []byte(content), 0644); err != nil {
					t.Fatalf("Failed to write packed-refs: %v", err)
				}
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					Version:  "",
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: "", // Go Git fails to parse this file, so we expect empty SHA
					},
				},
			},
		},
		{
			name: "Standard repo detached HEAD",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"), 0644); err != nil {
					t.Fatalf("Failed to write HEAD: %v", err)
				}
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					Version:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
					},
				},
			},
		},
		{
			name: "Standard repo with no remote URL",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dotGit, "config"), []byte("[core]\n\tbare = false\n"), 0644); err != nil {
					t.Fatalf("Failed to write config: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
					t.Fatalf("Failed to write HEAD: %v", err)
				}
				// Setup loose ref so it doesn't fail on commit resolution
				if err := os.MkdirAll(filepath.Join(dotGit, "refs", "heads"), 0755); err != nil {
					t.Fatalf("Failed to create refs dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dotGit, "refs", "heads", "main"), []byte(commitSHA+"\n"), 0644); err != nil {
					t.Fatalf("Failed to write ref file: %v", err)
				}
			},
			wantPackages: nil, // Expect 0 packages
		},
		{
			name: "Standard repo with missing HEAD",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				// HEAD is not created
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					Version:  "",
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: "",
					},
				},
			},
		},
		{
			name: "Standard repo with dangling ref and no packed-refs",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/dangling\n"), 0644); err != nil {
					t.Fatalf("Failed to write HEAD: %v", err)
				}
				// No loose ref created for dangling, and no packed-refs file
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					Version:  "",
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: "",
					},
				},
			},
		},
		{
			name: "Repo with multiple remotes and normalization",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				config := `
[remote "origin"]
	url = https://github.com/google/repo-foo.git
[remote "upstream"]
	url = git@github.com:google/repo-bar.git
[remote "mirror"]
	url = https://bitbucket.org/google/repo-foo.git
`
				if err := os.WriteFile(filepath.Join(dotGit, "config"), []byte(config), 0644); err != nil {
					t.Fatalf("Failed to write config: %v", err)
				}
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: "",
					},
				},
				{
					Name:     "repo-bar",
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-bar",
						Commit: "",
					},
				},
				{
					Name:     "repo-foo",
					PURLType: purl.TypeGeneric,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://bitbucket.org/google/repo-foo",
						Commit: "",
					},
				},
			},
		},
		{
			name: "Standard repo with missing config",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.Remove(filepath.Join(dotGit, "config")); err != nil {
					t.Fatalf("Failed to remove config: %v", err)
				}
			},
			wantErr: true,
		},

		{
			name: "Repo with submodule",
			path: ".git",
			setupSubtest: func(t *testing.T, dotGit string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
					t.Fatalf("Failed to write HEAD: %v", err)
				}
				if err := os.MkdirAll(filepath.Join(dotGit, "refs", "heads"), 0755); err != nil {
					t.Fatalf("Failed to create refs dir: %v", err)
				}
				repoRoot := filepath.Dir(dotGit)
				gitModulesContent := `
[submodule "submodule-bar"]
	path = sub/bar
	url = https://github.com/google/submodule-bar.git
`
				if err := os.WriteFile(filepath.Join(repoRoot, ".gitmodules"), []byte(gitModulesContent), 0644); err != nil {
					t.Fatalf("Failed to write .gitmodules: %v", err)
				}
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "repo-foo",
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath(".git"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/repo-foo",
						Commit: "",
					},
				},
				{
					Name:     "submodule-bar",
					PURLType: purl.TypeGithub,
					Location: extractor.LocationFromPath("sub/bar"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/google/submodule-bar",
						Commit: "",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			dotGit := filepath.Join(tempDir, ".git")
			if err := os.MkdirAll(dotGit, 0755); err != nil {
				t.Fatalf("Failed to create .git dir: %v", err)
			}
			// Default config
			if err := os.WriteFile(filepath.Join(dotGit, "config"), []byte(configContent), 0644); err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}

			extr, err := New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}

			if tt.setupSubtest != nil {
				tt.setupSubtest(t, dotGit)
			}

			scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				FakeScanRoot: tempDir,
				Path:         tt.path,
			})
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if (err != nil) != tt.wantErr {
				t.Errorf("Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(tt.wantPackages, got.Packages, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("Extract() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkDirExtractor_Extract(b *testing.B) {
	tempDir := b.TempDir()
	dotGit := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(dotGit, 0755); err != nil {
		b.Fatalf("Failed to create dir: %v", err)
	}

	configContent := `
[remote "origin"]
	url = https://github.com/google/osv-scalibr.git
`
	if err := os.WriteFile(filepath.Join(dotGit, "config"), []byte(configContent), 0644); err != nil {
		b.Fatalf("Failed to write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		b.Fatalf("Failed to write HEAD: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dotGit, "refs", "heads"), 0755); err != nil {
		b.Fatalf("Failed to create refs dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dotGit, "refs", "heads", "main"), []byte("1234567890abcdef1234567890abcdef12345678\n"), 0644); err != nil {
		b.Fatalf("Failed to write ref file: %v", err)
	}

	extr, err := New(&cpb.PluginConfig{})
	if err != nil {
		b.Fatalf("New failed: %v", err)
	}
	scanInput := extracttest.GenerateScanInputMock(b, extracttest.ScanInputMockConfig{
		FakeScanRoot: tempDir,
		Path:         ".git",
	})
	defer extracttest.CloseTestScanInput(b, scanInput)

	b.ResetTimer()
	for range b.N {
		_, _ = extr.Extract(b.Context(), &scanInput)
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "Empty", url: "", want: ""},
		{name: "HTTPS standard", url: "https://github.com/google/repo-foo", want: "https://github.com/google/repo-foo"},
		{name: "HTTPS with .git", url: "https://github.com/google/repo-foo.git", want: "https://github.com/google/repo-foo"},
		{name: "HTTP with .git", url: "http://github.com/google/repo-foo.git", want: "https://github.com/google/repo-foo"},
		{name: "SSH standard", url: "ssh://git@github.com/google/repo-foo.git", want: "https://github.com/google/repo-foo"},
		{name: "SCP-like SSH", url: "git@github.com:google/repo-foo.git", want: "https://github.com/google/repo-foo"},
		{name: "SCP-like SSH without .git", url: "git@github.com:google/repo-foo", want: "https://github.com/google/repo-foo"},
		{name: "File protocol", url: "file:///path/to/repo", want: "file:///path/to/repo"},
		{name: "Custom protocol", url: "custom://foo/bar.git", want: "custom://foo/bar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeURL(tt.url)
			if got != tt.want {
				t.Errorf("normalizeURL(%q) got = %q, want = %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseDomain(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/google/repo-foo.git", "github.com"},
		{"http://github.com/google/repo-foo.git", "github.com"},
		{"git@github.com:google/repo-foo.git", "github.com"},
		{"ssh://git@github.com/google/repo-foo.git", "github.com"},
		{"ssh://git@github.com:22/google/repo-foo.git", "github.com"},
		{"git://github.com/google/repo-foo.git", "github.com"},
		{"github.com/google/repo-foo.git", "github.com"},
		{"mygithub.com/google/repo-foo.git", "mygithub.com"},
		{"github.com.attacker.com/google/repo-foo.git", "github.com.attacker.com"},
		{"/path/to/github.com", ""},
		{"some-string", "some-string"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := parseDomain(tt.url)
			if got != tt.want {
				t.Errorf("parseDomain(%q) got = %q, want = %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestInferRepoName(t *testing.T) {
	tests := []struct {
		name      string
		remoteURL string
		dotGitDir string
		want      string
	}{
		{
			name:      "Standard HTTPS URL",
			remoteURL: "https://github.com/google/repo-foo.git",
			dotGitDir: "/foo/bar/.git",
			want:      "repo-foo",
		},
		{
			name:      "HTTPS URL without .git",
			remoteURL: "https://github.com/google/repo-foo",
			dotGitDir: "/foo/bar/.git",
			want:      "repo-foo",
		},
		{
			name:      "Non-URL string",
			remoteURL: "some-arbitrary-string",
			dotGitDir: "/foo/bar/.git",
			want:      "some-arbitrary-string",
		},
		{
			name:      "Empty remote URL",
			remoteURL: "",
			dotGitDir: "/foo/bar/.git",
			want:      "bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferRepoName(tt.remoteURL, tt.dotGitDir)
			if got != tt.want {
				t.Errorf("inferRepoName(%q, %q) got = %q, want = %q", tt.remoteURL, tt.dotGitDir, got, tt.want)
			}
		})
	}
}
