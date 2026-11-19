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

// wantPackage builds the package the extractor is expected to report for
// group:artifact@version declared on the given line, optionally inside
// dependency groups.
func wantPackage(path, group, artifact, version string, line int, groups ...string) *extractor.Package {
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
		refs     = "testdata/profile-references.clj"
		edge     = "testdata/reader-edge-cases.clj"
	)
	tests := []extracttest.TestTableEntry{
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.clj",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			// A Clojure file that is not a Leiningen project file.
			Name: "no_defproject",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-defproject.clj",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			// The defproject form is never closed.
			Name: "malformed",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed.clj",
			},
			WantErr: io.ErrUnexpectedEOF,
		},
		{
			// Namespaced and bare coordinates, trailing options, a plain Java
			// artifact and a :dev profile dependency. :plugins are build tools
			// and are not reported.
			Name: "basic",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: basic,
			},
			WantPackages: []*extractor.Package{
				wantPackage(basic, "org.clojure", "clojure", "1.11.1", 6),
				wantPackage(basic, "cheshire", "cheshire", "5.13.0", 7),
				wantPackage(basic, "ring", "ring-core", "1.12.2", 8),
				wantPackage(basic, "com.fasterxml.jackson.core", "jackson-databind", "2.9.8", 9),
				wantPackage(basic, "org.clojure", "test.check", "1.1.1", 11, "dev"),
			},
		},
		{
			// Versions come from :managed-dependencies or from ~sym references
			// to top-level string defs, with or without a docstring.
			// Dependencies whose version cannot be resolved are skipped, and
			// managed entries are not reported by themselves.
			Name: "managed_and_defs",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: managed,
			},
			WantPackages: []*extractor.Package{
				wantPackage(managed, "org.slf4j", "slf4j-api", "2.0.13", 8),
				wantPackage(managed, "ring", "ring-core", "1.12.2", 9),
				wantPackage(managed, "com.fasterxml.jackson.core", "jackson-databind", "2.15.2", 10),
			},
		},
		{
			// :classifier, :extension and :scope, and a coordinate written as a
			// string.
			Name: "options",
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
				wantPackage(options, "midje", "midje", "1.10.9", 4, "test"),
				wantPackage(options, "javax.servlet", "servlet-api", "2.5", 5, "provided"),
				wantPackage(options, "com.example", "explicit-compile", "2.0", 6),
				wantPackage(options, "com.example", "string-coord", "3.0", 7),
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
				wantPackage(profiles, "org.clojure", "clojure", "1.12.0", 2),
				wantPackage(profiles, "nrepl", "nrepl", "1.3.0", 3, "dev"),
				wantPackage(profiles, "org.clojure", "clojure", "1.12.0", 4, "provided"),
				wantPackage(profiles, "org.clojure", "test.check", "1.1.1", 7, "test"),
			},
		},
		{
			// Profiles that include other profiles by name. What a named
			// profile declares belongs to every default profile that includes
			// it, directly (:project/test), through another name (:shared,
			// which also refers back to :project/dev) or as the whole profile
			// (:provided). Names the file does not define (:profiles/dev) add
			// nothing, another default profile (:dev inside :test) is not
			// repeated, and profiles only reachable from opt-in ones
			// (:project/release, :1.11) are not reported.
			Name: "profile_references",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: refs,
			},
			WantPackages: []*extractor.Package{
				wantPackage(refs, "org.clojure", "clojure", "1.12.0", 3),
				wantPackage(refs, "org.example", "shared", "3.0", 12, "dev", "test"),
				wantPackage(refs, "abc", "xyz", "1.0.0", 8, "dev", "test"),
				wantPackage(refs, "nrepl", "nrepl", "1.3.0", 4, "dev"),
				wantPackage(refs, "org.example", "test-only", "2.0", 9, "test"),
				wantPackage(refs, "javax.servlet", "servlet-api", "2.5", 10, "provided"),
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
				wantPackage(edge, "org.clojure", "clojure", "1.11.1", 15),
				wantPackage(edge, "com.example", "after-discard", "2.0", 16),
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

// TestExtractor_Extract_InlineInput covers inputs that are easier to state
// inline than as fixture files: malformed structure, hostile nesting, line
// counting and entries that have to be skipped.
func TestExtractor_Extract_InlineInput(t *testing.T) {
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
			// Prefixes nest without any bracket, so they count towards the
			// limit as well.
			name:    "quotes_nested_deeper_than_the_limit",
			content: "(defproject a \"1\" :x " + strings.Repeat("'", 1000) + "x)",
			wantErr: extracttest.ContainsErrStr{Str: "nested deeper"},
		},
		{
			name:    "metadata_nested_deeper_than_the_limit",
			content: "(defproject a \"1\" :x " + strings.Repeat("^:m ", 1000) + "x)",
			wantErr: extracttest.ContainsErrStr{Str: "nested deeper"},
		},
		{
			name:    "tagged_literals_nested_deeper_than_the_limit",
			content: "(defproject a \"1\" :x " + strings.Repeat("#t ", 1000) + "x)",
			wantErr: extracttest.ContainsErrStr{Str: "nested deeper"},
		},
		{
			// #_ #_ a b discards both a and b: the discards nest.
			name:    "discards_nested_deeper_than_the_limit",
			content: "(defproject a \"1\" :x " + strings.Repeat("#_ ", 1000) + strings.Repeat("x ", 1001) + ")",
			wantErr: extracttest.ContainsErrStr{Str: "nested deeper"},
		},
		{
			// Discarded forms that follow each other do not nest, however many
			// there are.
			name: "many_discarded_forms_in_a_row",
			content: "(defproject a \"1\" :dependencies [" +
				strings.Repeat("#_[x \"0\"] ", 1000) + "[b \"1\"]])",
			wantPackages: []*extractor.Package{wantPackage("project.clj", "b", "b", "1", 1)},
		},
		{
			name:         "nested_discards",
			content:      `(defproject a "1" :dependencies [#_ #_ [x "0"] [y "0"] [b "1"]])`,
			wantPackages: []*extractor.Package{wantPackage("project.clj", "b", "b", "1", 1)},
		},
		{
			name:    "discard_with_nothing_after_it",
			content: `(defproject a "1" :dependencies [[b "1"] #_])`,
			wantErr: extracttest.ContainsErrStr{Str: "missing form"},
		},
		{
			name:    "discard_at_the_end_of_the_input",
			content: `(defproject a "1" :dependencies [[b "1"] #_`,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			// #! starts a comment that runs to the end of the line, whatever
			// the line holds.
			name: "shebang_line",
			content: "#!/bin/sh\n" +
				"#! not code: ( [ \" \n" +
				"(defproject a \"1\" :dependencies [[b \"1\"]])",
			wantPackages: []*extractor.Package{wantPackage("project.clj", "b", "b", "1", 3)},
		},
		{
			name:    "shebang_comment_inside_a_form",
			content: "(defproject a \"1\" :dependencies [[b \"1\"] #! [x \"0\"]\n [c \"2\"]])",
			wantPackages: []*extractor.Package{
				wantPackage("project.clj", "b", "b", "1", 1),
				wantPackage("project.clj", "c", "c", "2", 2),
			},
		},
		{
			// #^ is the older spelling of ^.
			name: "old_style_metadata",
			content: `(defproject a "1" :dependencies #^:replace [[b "1"]]` +
				` :profiles {:dev #^{:pom-scope :test} {:dependencies [[c "2"]]}})`,
			wantPackages: []*extractor.Package{
				wantPackage("project.clj", "b", "b", "1", 1),
				wantPackage("project.clj", "c", "c", "2", 1, "dev"),
			},
		},
		{
			// ^ and ~ end the token before them, as in the Clojure reader.
			name:         "prefix_right_after_a_token",
			content:      "(def v \"1\")\n(defproject a \"1\" :dependencies^:replace [[b~v]])",
			wantPackages: []*extractor.Package{wantPackage("project.clj", "b", "b", "1", 2)},
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
				wantPackage("project.clj", "org.clojure", "clojure", "1.11.1", 2),
				wantPackage("project.clj", "cheshire", "cheshire", "5.13.0", 3),
			},
		},
		{
			name:         "forms_after_defproject_are_not_read",
			content:      "(defproject a \"1\" :dependencies [[b \"1\"]])\n(this is (not closed",
			wantPackages: []*extractor.Package{wantPackage("project.clj", "b", "b", "1", 1)},
		},
		{
			name:         "dependencies_given_as_an_expression_are_skipped",
			content:      `(defproject a "1" :dependencies ~(concat base-deps extra-deps))`,
			wantPackages: []*extractor.Package{},
		},
		{
			// Var quotes, symbolic values, namespaced maps, unquote splicing,
			// deref, syntax quote and string escapes are read without
			// disturbing what follows.
			name: "other_reader_syntax",
			content: "(defproject a \"1\" :x [#'v ##Inf #:ns{:k 1} ~@xs @r `q \"a\\nb\\tc\\\"d\"]\n" +
				" :dependencies [[b \"1\"]])",
			wantPackages: []*extractor.Package{wantPackage("project.clj", "b", "b", "1", 2)},
		},
		{
			// Only (def name "value") and (def name "docstring" "value") give
			// a version.
			name: "defs_that_are_not_plain_strings",
			content: `(def) (def 1 "x") (def v 2) (def w "doc" 3) (def u "a" "b" "c")
				(defproject a "1" :dependencies [[b ~v] [c ~w] [d ~u] [e ~1] [f "1"]])`,
			wantPackages: []*extractor.Package{wantPackage("project.clj", "f", "f", "1", 2)},
		},
		{
			name: "malformed_dependency_entries_are_skipped",
			content: `(defproject a "1"
				:dependencies [[] not-a-vector [1 "2"] [/ "1"] [x 5] [y ~(str "1")] [b "1"] [c "2" :classifier]]
				:profiles {"dev" {:dependencies [[z "9"]]}})`,
			wantPackages: []*extractor.Package{
				wantPackage("project.clj", "b", "b", "1", 2),
				wantPackage("project.clj", "c", "c", "2", 2),
			},
		},
		{
			// One declaration is one package, however many default profiles
			// include it and even when it is written twice.
			name: "dependency_reached_through_two_profiles",
			content: `(defproject a "1"
				:profiles {:dev [:shared] :test [:shared]
				           :shared {:dependencies [[b "1"] [b "1"] [c "2" :scope "test"]]}})`,
			wantPackages: []*extractor.Package{
				wantPackage("project.clj", "b", "b", "1", 3, "dev", "test"),
				wantPackage("project.clj", "c", "c", "2", 3, "dev", "test"),
			},
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
	extr, err := projectclj.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("projectclj.New() error: %v", err)
	}
	inv, err := extr.Extract(t.Context(), &filesystem.ScanInput{
		Path: "project.clj",
		Reader: strings.NewReader(`(defproject a "1" :dependencies [[org.clojure/clojure "1.11.1"]
			[cheshire "5.13.0"]
			[org.lwjgl/lwjgl "3.3.3" :classifier "natives-linux"]])`),
	})
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	got := []string{}
	for _, p := range inv.Packages {
		got = append(got, p.PURL().String())
	}
	want := []string{
		"pkg:maven/org.clojure/clojure@1.11.1",
		"pkg:maven/cheshire/cheshire@5.13.0",
		"pkg:maven/org.lwjgl/lwjgl@3.3.3?classifier=natives-linux",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("PURLs diff (-want +got):\n%s", diff)
	}
}

var _ filesystem.Extractor = projectclj.Extractor{}
