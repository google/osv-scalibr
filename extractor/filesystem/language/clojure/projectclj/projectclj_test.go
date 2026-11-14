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

package projectclj_test

import (
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/clojure/projectclj"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

// maven builds the package the extractor reports for group:artifact@version
// declared on the given line, optionally inside dependency groups.
func maven(path, group, artifact, version string, line int, groups ...string) *extractor.Package {
	return &extractor.Package{
		Name:     group + ":" + artifact,
		Version:  version,
		PURLType: purl.TypeMaven,
		Metadata: &javalockfile.Metadata{
			ArtifactID:   artifact,
			GroupID:      group,
			DepGroupVals: groups,
		},
		Location: extractor.LocationFromPathAndLine(path, line),
	}
}

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name             string
		inputPath        string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		want             bool
	}{
		{
			name:      "empty_path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "project.clj_at_the_root",
			inputPath: "project.clj",
			want:      true,
		},
		{
			name:      "nested_project.clj",
			inputPath: "path/to/my/project.clj",
			want:      true,
		},
		{
			name:      "project.clj_used_as_a_directory_name",
			inputPath: "path/to/my/project.clj/file",
			want:      false,
		},
		{
			name:      "project.clj_as_a_filename_suffix",
			inputPath: "path/to/my/old-project.clj",
			want:      false,
		},
		{
			name:      "clojurescript_file_is_not_ours",
			inputPath: "path/to/my/project.cljs",
			want:      false,
		},
		{
			name:      "user_profiles_file_is_not_a_project",
			inputPath: "path/to/.lein/profiles.clj",
			want:      false,
		},
		{
			name:      "deps.edn_is_not_ours",
			inputPath: "path/to/my/deps.edn",
			want:      false,
		},
		{
			name:             "file_below_the_size_limit",
			inputPath:        "project.clj",
			fileSizeBytes:    100,
			maxFileSizeBytes: 1000,
			want:             true,
		},
		{
			name:             "file_above_the_size_limit",
			inputPath:        "project.clj",
			fileSizeBytes:    10000,
			maxFileSizeBytes: 1000,
			want:             false,
		},
		{
			name:             "size_limit_disabled",
			inputPath:        "project.clj",
			fileSizeBytes:    10000,
			maxFileSizeBytes: 0,
			want:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := projectclj.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("projectclj.New() error: %v", err)
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
	const (
		basic    = "testdata/basic.clj"
		managed  = "testdata/managed-and-defs.clj"
		options  = "testdata/options.clj"
		profiles = "testdata/profiles.clj"
		edge     = "testdata/reader-edge-cases.clj"
	)
	tests := []extracttest.TestTableEntry{
		{
			Name: "empty_file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.clj",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "clojure_file_without_defproject",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-defproject.clj",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "unterminated_defproject_is_an_error",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed.clj",
			},
			WantErr: io.ErrUnexpectedEOF,
		},
		{
			// Namespaced and bare coordinates, trailing options, a plain Java
			// artifact and a :dev profile dependency. :plugins are build tools
			// and are not reported.
			Name: "typical_project",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: basic,
			},
			WantPackages: []*extractor.Package{
				maven(basic, "org.clojure", "clojure", "1.11.1", 6),
				maven(basic, "cheshire", "cheshire", "5.13.0", 7),
				maven(basic, "ring", "ring-core", "1.12.2", 8),
				maven(basic, "com.fasterxml.jackson.core", "jackson-databind", "2.9.8", 9),
				maven(basic, "org.clojure", "test.check", "1.1.1", 11, "dev"),
			},
		},
		{
			// Versions come from :managed-dependencies or from ~sym references
			// to top-level string defs. Dependencies whose version cannot be
			// resolved are skipped, and managed entries are not reported by
			// themselves.
			Name: "managed_dependencies_and_def_versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: managed,
			},
			WantPackages: []*extractor.Package{
				maven(managed, "org.slf4j", "slf4j-api", "2.0.13", 7),
				maven(managed, "ring", "ring-core", "1.12.2", 8),
				maven(managed, "com.fasterxml.jackson.core", "jackson-databind", "2.15.2", 9),
			},
		},
		{
			Name: "dependency_options",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: options,
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.lwjgl:lwjgl",
					Version:  "3.3.3",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "lwjgl",
						GroupID:    "org.lwjgl",
						Classifier: "natives-linux",
					},
					Location: extractor.LocationFromPathAndLine(options, 2),
				},
				{
					Name:     "com.example:bundle",
					Version:  "1.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "bundle",
						GroupID:    "com.example",
						Type:       "pom",
					},
					Location: extractor.LocationFromPathAndLine(options, 3),
				},
				maven(options, "midje", "midje", "1.10.9", 4, "test"),
				maven(options, "javax.servlet", "servlet-api", "2.5", 5, "provided"),
				maven(options, "com.example", "explicit-compile", "2.0", 6),
				maven(options, "com.example", "string-coord", "3.0", 7),
			},
		},
		{
			// Composite profiles, ^:replace metadata, a profile without
			// dependencies, a :scope matching the profile name, and an opt-in
			// :1.10 profile whose dependency is not reported.
			Name: "profiles",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: profiles,
			},
			WantPackages: []*extractor.Package{
				maven(profiles, "org.clojure", "clojure", "1.12.0", 2),
				maven(profiles, "nrepl", "nrepl", "1.3.0", 3, "dev"),
				maven(profiles, "org.clojure", "clojure", "1.12.0", 4, "provided"),
				maven(profiles, "org.clojure", "test.check", "1.1.1", 7, "test"),
			},
		},
		{
			// Delimiters inside strings, comments, regexes and character
			// literals, plus sets, tagged literals, anonymous functions, reader
			// conditionals and #_ discarded dependencies.
			Name: "reader_edge_cases",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: edge,
			},
			WantPackages: []*extractor.Package{
				maven(edge, "org.clojure", "clojure", "1.11.1", 15),
				maven(edge, "com.example", "after-discard", "2.0", 16),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := projectclj.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("projectclj.New() error: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if tt.WantErr != nil {
				wantInv = inventory.Inventory{}
			}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}

// TestExtractor_Reader covers inputs that are easier to state inline than as
// fixture files: malformed structure, hostile nesting and line counting.
func TestExtractor_Reader(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name:    "mismatched_closing_delimiter",
			content: `(defproject a "1" :dependencies [[b "1"]})`,
			wantErr: extracttest.ContainsErrStr{Str: "expected"},
		},
		{
			name:    "stray_closing_delimiter_before_defproject",
			content: ") (defproject a \"1\" :dependencies [[b \"1\"]])",
			wantErr: extracttest.ContainsErrStr{Str: "unexpected closing delimiter"},
		},
		{
			name:    "nesting_deeper_than_the_limit",
			content: "(defproject a \"1\" :x " + strings.Repeat("[", 1000) + strings.Repeat("]", 1000) + ")",
			wantErr: extracttest.ContainsErrStr{Str: "nested deeper"},
		},
		{
			name:    "reader_prefix_with_nothing_after_it",
			content: `(defproject a "1" :dependencies [[b "1"] ^])`,
			wantErr: extracttest.ContainsErrStr{Str: "missing form"},
		},
		{
			name: "windows_line_endings_keep_line_numbers",
			content: "(defproject a \"1\"\r\n" +
				"  :dependencies [[org.clojure/clojure \"1.11.1\"]\r\n" +
				"                 [cheshire \"5.13.0\"]])\r\n",
			wantPackages: []*extractor.Package{
				maven("project.clj", "org.clojure", "clojure", "1.11.1", 2),
				maven("project.clj", "cheshire", "cheshire", "5.13.0", 3),
			},
		},
		{
			name:         "forms_after_defproject_are_not_read",
			content:      "(defproject a \"1\" :dependencies [[b \"1\"]])\n(this is (not closed",
			wantPackages: []*extractor.Package{maven("project.clj", "b", "b", "1", 1)},
		},
		{
			name:         "dependencies_given_as_an_expression_are_skipped",
			content:      `(defproject a "1" :dependencies ~(concat base-deps extra-deps))`,
			wantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr, err := projectclj.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("projectclj.New() error: %v", err)
			}
			got, err := extr.Extract(t.Context(), &filesystem.ScanInput{
				Path:   "project.clj",
				Reader: strings.NewReader(tt.content),
			})
			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Extract() error diff (-want +got):\n%s", diff)
			}
			if tt.wantErr != nil {
				return
			}
			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("Extract() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestExtractor_PURL checks that reported packages map to Maven PURLs with
// the group as namespace, since that is what vulnerability matching keys off.
func TestExtractor_PURL(t *testing.T) {
	got := maven("project.clj", "org.clojure", "clojure", "1.11.1", 1).PURL()
	want := "pkg:maven/org.clojure/clojure@1.11.1"
	if got == nil || got.String() != want {
		t.Errorf("PURL() got = %v, want %q", got, want)
	}
}

var _ filesystem.Extractor = projectclj.Extractor{}
