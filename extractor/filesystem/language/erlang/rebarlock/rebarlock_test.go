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

package rebarlock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/rebarlock"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name             string
		inputPath        string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		want             bool
	}{
		{
			name:      "empty path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "rebar.lock at the root",
			inputPath: "rebar.lock",
			want:      true,
		},
		{
			name:      "nested rebar.lock",
			inputPath: "path/to/my/rebar.lock",
			want:      true,
		},
		{
			name:      "rebar.lock used as a directory name",
			inputPath: "path/to/my/rebar.lock/file",
			want:      false,
		},
		{
			name:      "rebar.lock as a filename prefix",
			inputPath: "path/to/my/rebar.lock.file",
			want:      false,
		},
		{
			name:      "rebar.lock as a filename suffix",
			inputPath: "path/to/my/backup.rebar.lock",
			want:      false,
		},
		{
			name:      "the elixir lockfile is not ours",
			inputPath: "path/to/my/mix.lock",
			want:      false,
		},
		{
			name:      "rebar.config is not a lockfile",
			inputPath: "path/to/my/rebar.config",
			want:      false,
		},
		{
			name:             "file below the size limit",
			inputPath:        "rebar.lock",
			fileSizeBytes:    100,
			maxFileSizeBytes: 1000,
			want:             true,
		},
		{
			name:             "file above the size limit",
			inputPath:        "rebar.lock",
			fileSizeBytes:    10000,
			maxFileSizeBytes: 1000,
			want:             false,
		},
		{
			name:             "size limit disabled",
			inputPath:        "rebar.lock",
			fileSizeBytes:    10000,
			maxFileSizeBytes: 0,
			want:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := rebarlock.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("rebarlock.New() error: %v", err)
			}

			fileInfo := fakefs.FakeFileInfo{
				FileName: tt.inputPath,
				FileMode: 0777,
				FileSize: tt.fileSizeBytes,
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, fileInfo))
			if got != tt.want {
				t.Errorf("FileRequired(%q) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "empty lockfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "malformed lockfile yields no packages and no error",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-a-lock.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cowlib",
					Version:  "2.11.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/one-package.lock"),
				},
			},
		},
		{
			Name: "direct and transitive packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cowboy",
					Version:  "2.9.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/two-packages.lock"),
				},
				{
					Name:     "ranch",
					Version:  "1.8.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/two-packages.lock"),
				},
			},
		},
		{
			// The hex.pm package name, not the OTP application name, is what
			// vulnerability feeds key off.
			Name: "app name differing from the hex package name",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/differing-app-name.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "uuid_erl",
					Version:  "2.0.1",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/differing-app-name.lock"),
				},
				{
					Name:     "quickrand",
					Version:  "2.0.7",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/differing-app-name.lock"),
				},
			},
		},
		{
			Name: "git and git_subdir dependencies wrapped across lines",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "gradualizer",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/git.lock"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/josefs/Gradualizer.git",
						Commit: "3021d29d82741399d131e3be38d2a8db79d146d4",
					},
				},
				{
					Name:     "yamerl",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/git.lock"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/erlang-ls/yamerl.git",
						Commit: "9a9f7a2e84554992f2e8e08a8060bfe97776a5b7",
					},
				},
				{
					Name:     "nested_app",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/git.lock"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/my-org/umbrella.git",
						Commit: "bef3ee1d3618017061498b96c75043e8449ef9b5",
					},
				},
			},
		},
		{
			Name: "legacy lockfile without the version envelope",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/legacy-format.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "meck",
					Version:  "0.8.13",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/legacy-format.lock"),
				},
				{
					Name:     "legacy_dep",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/legacy-format.lock"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/my-org/legacy_dep.git",
						Commit: "a9574ab75d6ed01e1288c453ae1d943d7a964595",
					},
				},
			},
		},
		{
			// A Mercurial changeset ID is not a git commit, so hg deps are
			// skipped rather than reported against the GIT ecosystem.
			Name: "mercurial dependencies are skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/mercurial.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cowlib",
					Version:  "2.11.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/mercurial.lock"),
				},
			},
		},
		{
			Name: "many mixed dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/many.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cache_tab",
					Version:  "1.0.34",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/many.lock"),
				},
				{
					Name:     "eimp",
					Version:  "1.0.27",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/many.lock"),
				},
				{
					Name:     "fast_tls",
					Version:  "1.1.26",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/many.lock"),
				},
				{
					Name:     "idna",
					Version:  "7.1.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/many.lock"),
				},
				{
					Name:     "jose",
					Version:  "1.11.12",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/many.lock"),
				},
				{
					Name:     "p1_utils",
					Version:  "1.0.29",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/many.lock"),
				},
				{
					Name:     "fast_xml",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/many.lock"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/processone/fast_xml",
						Commit: "ee0e6569f44659327a022c0d23d193d1c3e72288",
					},
				},
				{
					Name:     "xmpp",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/many.lock"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/processone/xmpp",
						Commit: "02893ce01f4d761659988edd85de99d24ccd6bdf",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := rebarlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("rebarlock.New() error: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}

// TestExtractor_PURL checks that the generated PURLs point at the right
// ecosystems, since that is what vulnerability matching keys off.
func TestExtractor_PURL(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want string
	}{
		{
			name: "hex package",
			pkg: &extractor.Package{
				Name:     "cowboy",
				Version:  "2.9.0",
				PURLType: purl.TypeHex,
			},
			want: "pkg:hex/cowboy@2.9.0",
		},
		{
			name: "git pinned package",
			pkg: &extractor.Package{
				Name:     "fast_xml",
				PURLType: purl.TypeGit,
				SourceCode: &extractor.SourceCodeIdentifier{
					Repo:   "https://github.com/processone/fast_xml",
					Commit: "ee0e6569f44659327a022c0d23d193d1c3e72288",
				},
			},
			want: "pkg:git/fast_xml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkg.PURL()
			if got == nil {
				t.Fatalf("PURL() got nil, want %q", tt.want)
			}
			if got.String() != tt.want {
				t.Errorf("PURL() got = %q, want %q", got.String(), tt.want)
			}
		})
	}
}

var _ filesystem.Extractor = rebarlock.Extractor{}
