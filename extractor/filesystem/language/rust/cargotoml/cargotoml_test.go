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

package cargotoml

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
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
		{
			name:      "Empty path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "Cargo.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.toml/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.toml.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.Cargo.toml",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "Invalid toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "Invalid dependency toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-dependency.toml",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-dependency.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/no-dependency.toml", 2),
				},
			},
		},
		{
			Name: "dependency with only version specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-version-dependency.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/only-version-dependency.toml", 2),
				},
				{
					Name:     "regex",
					Version:  "0.0.1",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/only-version-dependency.toml", 6),
				},
			},
		},
		{
			// dependencies with only tag specified should be skipped
			Name: "git dependency with tag specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency-tagged.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/git-dependency-tagged.toml", 2),
				},
			},
		},
		{
			Name: "git dependency with commit specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency-with-commit.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/git-dependency-with-commit.toml", 2),
				},
				{
					Name:     "regex",
					PURLType: purl.TypeCargo,
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/rust-lang/regex.git",
						Commit: "0c0990399270277832fbb5b91a1fa118e6f63dba",
					},
					Location: extractor.LocationFromPathAndLine("testdata/git-dependency-with-commit.toml", 6),
				},
			},
		},
		{
			Name: "git dependency with pr rev specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency-with-pr.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/git-dependency-with-pr.toml", 2),
				},
			},
		},
		{
			Name: "two dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-dependencies.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/two-dependencies.toml", 2),
				},
				{
					Name:     "futures",
					Version:  "0.3",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/two-dependencies.toml", 7),
				},
			},
		},
		{
			Name: "empty toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "",
					Version:  "",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPath("testdata/empty.toml"),
				},
			},
		},
		{
			Name: "duplicate dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/duplicate.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/duplicate.toml", 2),
				},
				{
					Name:     "regex",
					Version:  "0.0.1",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/duplicate.toml", 6),
				},
			},
		},
		{
			Name: "table dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/table-header-dependency.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/table-header-dependency.toml", 2),
				},
				{
					Name:     "regex",
					Version:  "0.0.1",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/table-header-dependency.toml", 5),
				},
			},
		},
		{
			Name: "package with comments",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/package-with-comments.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hello_world",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/package-with-comments.toml", 2),
				},
				{
					Name:     "regex",
					Version:  "0.0.1",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/package-with-comments.toml", 6),
				},
			},
		},
		{
			Name: "dependency with name clashing with root package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/clashing-package-name.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "regex",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/clashing-package-name.toml", 2),
				},
				{
					Name:     "regex",
					Version:  "0.0.1",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/clashing-package-name.toml", 6),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New: %v", err)
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

func TestFindLineNumbers(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		deps      map[string]cargoTomlDependency
		wantLines map[string]int
	}{
		{
			name: "standard package and dependencies",
			content: `[package]
name = "my_crate"
version = "1.0.0"

[dependencies]
serde = "1.0"
regex = "1.5"
`,
			deps: map[string]cargoTomlDependency{
				"serde": {Version: "1.0"},
				"regex": {Version: "1.5"},
			},
			wantLines: map[string]int{
				"":      2,
				"serde": 6,
				"regex": 7,
			},
		},
		{
			name: "dependency not in deps map is ignored",
			content: `[package]
name = "my_crate"

[dependencies]
unused = "1.0"
`,
			deps: map[string]cargoTomlDependency{},
			wantLines: map[string]int{
				"": 2,
			},
		},
		{
			name:      "empty content",
			content:   "",
			deps:      map[string]cargoTomlDependency{"serde": {Version: "1.0"}},
			wantLines: map[string]int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findLineNumbers([]byte(tt.content), tt.deps)
			if diff := cmp.Diff(tt.wantLines, got); diff != "" {
				t.Errorf("findLineNumbers() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseTableHeader(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantHeader string
		wantOK     bool
	}{
		{
			name:       "valid section header",
			line:       "  [package]  ",
			wantHeader: "package",
			wantOK:     true,
		},
		{
			name:       "valid dependencies header",
			line:       "[dependencies.regex]",
			wantHeader: "dependencies.regex",
			wantOK:     true,
		},
		{
			name:       "valid quoted dependencies header",
			line:       `[dependencies."foo.bar"]`,
			wantHeader: `dependencies."foo.bar"`,
			wantOK:     true,
		},
		{
			name:       "missing closing bracket",
			line:       "[package",
			wantHeader: "",
			wantOK:     false,
		},
		{
			name:       "missing opening bracket",
			line:       "package]",
			wantHeader: "",
			wantOK:     false,
		},
		{
			name:       "not a bracket",
			line:       `name = "hello"`,
			wantHeader: "",
			wantOK:     false,
		},
		{
			name:       "empty line",
			line:       "",
			wantHeader: "",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHeader, gotOK := parseTableHeader(tt.line)
			if gotHeader != tt.wantHeader || gotOK != tt.wantOK {
				t.Errorf("parseTableHeader(%q) = (%q, %v), want (%q, %v)", tt.line, gotHeader, gotOK, tt.wantHeader, tt.wantOK)
			}
		})
	}
}

func TestParseDependencyFromHeader(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantDep string
		wantOK  bool
	}{
		{
			name:    "simple dependency header",
			header:  "dependencies.regex",
			wantDep: "regex",
			wantOK:  true,
		},
		{
			name:    "quoted dependency header",
			header:  `dependencies."foo.bar"`,
			wantDep: "foo.bar",
			wantOK:  true,
		},
		{
			name:    "single quoted dependency header",
			header:  "dependencies.'foo_bar'",
			wantDep: "foo_bar",
			wantOK:  true,
		},
		{
			name:    "spaced dependency header",
			header:  `dependencies. "foo" `,
			wantDep: "foo",
			wantOK:  true,
		},
		{
			name:    "non dependency header",
			header:  "package",
			wantDep: "",
			wantOK:  false,
		},
		{
			name:    "flat dependencies header",
			header:  "dependencies",
			wantDep: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDep, gotOK := parseDependencyFromHeader(tt.header)
			if gotDep != tt.wantDep || gotOK != tt.wantOK {
				t.Errorf("parseDependencyFromHeader(%q) = (%q, %v), want (%q, %v)", tt.header, gotDep, gotOK, tt.wantDep, tt.wantOK)
			}
		})
	}
}

func TestParseKey(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantKey string
		wantOK  bool
	}{
		{
			name:    "valid key value",
			line:    `name = "hello_world"`,
			wantKey: "name",
			wantOK:  true,
		},
		{
			name:    "single quotes",
			line:    `'version' = '1.0'`,
			wantKey: "version",
			wantOK:  true,
		},
		{
			name:    "double quoted key",
			line:    `"dependencies.foo" = "1.0"`,
			wantKey: "dependencies.foo",
			wantOK:  true,
		},
		{
			name:    "with whitespace",
			line:    `  key   =   "val"  `,
			wantKey: "key",
			wantOK:  true,
		},
		{
			name:    "multiple equal signs in value",
			line:    `url = "https://foo=bar"`,
			wantKey: "url",
			wantOK:  true,
		},
		{
			name:    "no equal sign",
			line:    "hello_world",
			wantKey: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotOK := parseKey(tt.line)
			if gotKey != tt.wantKey || gotOK != tt.wantOK {
				t.Errorf("parseKey(%q) = (%q, %v), want (%q, %v)", tt.line, gotKey, gotOK, tt.wantKey, tt.wantOK)
			}
		})
	}
}
