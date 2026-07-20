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

package vsix_test

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/vsix"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

// makeVSIX builds an in-memory .vsix (ZIP) archive from the provided entries.
// Each entry is a (name, content) pair.
func makeVSIX(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip.Create(%q): %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip.Write(%q): %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	return buf.Bytes()
}

// pkgLoc is a test helper that builds the expected PackageLocation for a
// package found at entryPath inside vsixPath.
func pkgLoc(vsixPath, entryPath string) extractor.PackageLocation {
	vsixLoc := location.FromPath(vsixPath)
	entryLoc := location.FromPath(vsixPath + "/" + entryPath)
	return extractor.PackageLocation{
		Descriptor: &vsixLoc,
		Related:    []location.Location{entryLoc},
	}
}

// ─── FileRequired ────────────────────────────────────────────────────────────

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "vsix at root",
			path:             "prettier.vsix",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "vsix in subdirectory",
			path:             "registry/extensions/golang.go-0.46.vsix",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "vsix uppercase extension",
			path:             "extension.VSIX",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "not a vsix — js file",
			path:         "extension.js",
			wantRequired: false,
		},
		{
			name:         "not a vsix — zip file",
			path:         "archive.zip",
			wantRequired: false,
		},
		{
			name:         "not a vsix — no extension",
			path:         "vsixfile",
			wantRequired: false,
		},
		{
			name:             "vsix within size limit",
			path:             "large.vsix",
			fileSizeBytes:    100 * units.MiB,
			maxFileSizeBytes: 500 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "vsix exactly at size limit",
			path:             "large.vsix",
			fileSizeBytes:    500 * units.MiB,
			maxFileSizeBytes: 500 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "vsix exceeds size limit",
			path:             "huge.vsix",
			fileSizeBytes:    600 * units.MiB,
			maxFileSizeBytes: 500 * units.MiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()

			e, err := vsix.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("vsix.New: %v", err)
			}
			e.(*vsix.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1 * units.KiB
			}

			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))

			if got != tt.wantRequired {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.wantRequired)
			}

			gotMetric := collector.FileRequiredResult(tt.path)
			if gotMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%q) metric = %v, want %v", tt.path, gotMetric, tt.wantResultMetric)
			}
		})
	}
}

// ─── Extract ─────────────────────────────────────────────────────────────────

func TestExtract(t *testing.T) {
	const vsixPath = "registry/prettier-vscode-11.0.0.vsix"

	tests := []struct {
		name             string
		vsixPath         string
		vsixData         []byte
		wantPackages     []*extractor.Package
		wantErr          bool
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:     "single npm dependency in node_modules",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				// Extension manifest — must be skipped.
				"extension/package.json": `{"name":"prettier-vscode","version":"11.0.0","engines":{"vscode":"^1.0.0"}}`,
				// Bundled npm dependency — must be extracted.
				"extension/node_modules/lodash/package.json": `{"name":"lodash","version":"4.17.21"}`,
			}),
			wantPackages: []*extractor.Package{
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: pkgLoc(vsixPath, "extension/node_modules/lodash/package.json"),
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "multiple npm dependencies",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				"extension/package.json":                                           `{"name":"some-ext","version":"1.0.0","engines":{"vscode":"^1.0.0"}}`,
				"extension/node_modules/lodash/package.json":                       `{"name":"lodash","version":"4.17.21"}`,
				"extension/node_modules/semver/package.json":                       `{"name":"semver","version":"7.5.4"}`,
				"extension/node_modules/lodash/node_modules/left-pad/package.json": `{"name":"left-pad","version":"1.3.0"}`,
			}),
			wantPackages: []*extractor.Package{
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: pkgLoc(vsixPath, "extension/node_modules/lodash/package.json"),
				},
				{
					Name:     "semver",
					Version:  "7.5.4",
					PURLType: purl.TypeNPM,
					Location: pkgLoc(vsixPath, "extension/node_modules/semver/package.json"),
				},
				{
					Name:     "left-pad",
					Version:  "1.3.0",
					PURLType: purl.TypeNPM,
					Location: pkgLoc(vsixPath, "extension/node_modules/lodash/node_modules/left-pad/package.json"),
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "extension manifest at root is skipped (no node_modules in path)",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				// Only the extension manifest — no node_modules at all.
				"extension/package.json": `{"name":"my-ext","version":"2.0.0","engines":{"vscode":"^1.0.0"}}`,
			}),
			// Empty: the manifest is filtered out.
			wantPackages:     []*extractor.Package{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "package.json with missing name is skipped",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				"extension/node_modules/bad/package.json": `{"version":"1.0.0"}`,
			}),
			wantPackages:     []*extractor.Package{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "package.json with missing version is skipped",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				"extension/node_modules/bad/package.json": `{"name":"some-pkg"}`,
			}),
			wantPackages:     []*extractor.Package{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "package.json with whitespace-only name and version is skipped",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				"extension/node_modules/bad/package.json": `{"name":"  ","version":"  "}`,
			}),
			wantPackages:     []*extractor.Package{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "malformed JSON entry is skipped — rest of archive extracted",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				"extension/node_modules/corrupt/package.json": `{NOT VALID JSON`,
				"extension/node_modules/lodash/package.json":  `{"name":"lodash","version":"4.17.21"}`,
			}),
			wantPackages: []*extractor.Package{
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: pkgLoc(vsixPath, "extension/node_modules/lodash/package.json"),
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "non-package.json entries are ignored",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				"[Content_Types].xml":                    `<?xml version="1.0"?>`,
				"extension.vsixmanifest":                 `<PackageManifest/>`,
				"extension/node_modules/ms/index.js":     `module.exports = function(){};`,
				"extension/node_modules/ms/package.json": `{"name":"ms","version":"2.1.3"}`,
			}),
			wantPackages: []*extractor.Package{
				{
					Name:     "ms",
					Version:  "2.1.3",
					PURLType: purl.TypeNPM,
					Location: pkgLoc(vsixPath, "extension/node_modules/ms/package.json"),
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid ZIP returns empty inventory without error",
			vsixPath:         vsixPath,
			vsixData:         []byte("this is not a zip file"),
			wantPackages:     []*extractor.Package{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "provenance — Related field carries internal entry path",
			vsixPath: "repo/golang.go-0.46.vsix",
			vsixData: makeVSIX(t, map[string]string{
				"extension/node_modules/vscode-languageclient/package.json": `{"name":"vscode-languageclient","version":"8.1.0"}`,
			}),
			wantPackages: []*extractor.Package{
				{
					Name:     "vscode-languageclient",
					Version:  "8.1.0",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("repo/golang.go-0.46.vsix", "extension/node_modules/vscode-languageclient/package.json"),
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:     "scoped npm package name preserved",
			vsixPath: vsixPath,
			vsixData: makeVSIX(t, map[string]string{
				"extension/node_modules/@babel/core/package.json": `{"name":"@babel/core","version":"7.22.0"}`,
			}),
			wantPackages: []*extractor.Package{
				{
					Name:     "@babel/core",
					Version:  "7.22.0",
					PURLType: purl.TypeNPM,
					Location: pkgLoc(vsixPath, "extension/node_modules/@babel/core/package.json"),
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty archive produces empty inventory",
			vsixPath:         vsixPath,
			vsixData:         makeVSIX(t, map[string]string{}),
			wantPackages:     []*extractor.Package{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()

			e, err := vsix.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("vsix.New: %v", err)
			}
			e.(*vsix.Extractor).Stats = collector

			vsixPathToUse := vsixPath
			if tt.vsixPath != "" {
				vsixPathToUse = tt.vsixPath
			}

			input := &filesystem.ScanInput{
				Path:   vsixPathToUse,
				Reader: bytes.NewReader(tt.vsixData),
				Info: fakefs.FakeFileInfo{
					FileName: filepath.Base(vsixPathToUse),
					FileMode: fs.ModePerm,
					FileSize: int64(len(tt.vsixData)),
				},
			}

			got, err := e.Extract(t.Context(), input)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Extract() error = %v, wantErr = %v", err, tt.wantErr)
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}

			if diff := cmp.Diff(
				wantInv, got,
				cmpopts.SortSlices(func(a, b *extractor.Package) bool {
					return a.Name < b.Name
				}),
				cmpopts.EquateEmpty(),
			); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}

			// Verify stats metrics were recorded correctly.
			wantResultMetric := tt.wantResultMetric
			if wantResultMetric == "" && !tt.wantErr {
				wantResultMetric = stats.FileExtractedResultSuccess
			}
			gotResultMetric := collector.FileExtractedResult(vsixPathToUse)
			if gotResultMetric != wantResultMetric {
				t.Errorf("Extract() metric = %v, want %v", gotResultMetric, wantResultMetric)
			}
		})
	}
}

func TestExtractFromTestdata(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantPackages []*extractor.Package
	}{
		{
			name: "single dependency",
			path: "testdata/single_dependency.vsix",
			wantPackages: []*extractor.Package{
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/single_dependency.vsix", "extension/node_modules/lodash/package.json"),
				},
			},
		},
		{
			name: "multiple dependencies",
			path: "testdata/multiple_dependencies.vsix",
			wantPackages: []*extractor.Package{
				{
					Name:     "left-pad",
					Version:  "1.3.0",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/multiple_dependencies.vsix", "extension/node_modules/lodash/node_modules/left-pad/package.json"),
				},
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/multiple_dependencies.vsix", "extension/node_modules/lodash/package.json"),
				},
				{
					Name:     "semver",
					Version:  "7.5.4",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/multiple_dependencies.vsix", "extension/node_modules/semver/package.json"),
				},
			},
		},
		{
			name: "scoped package",
			path: "testdata/scoped_package.vsix",
			wantPackages: []*extractor.Package{
				{
					Name:     "@babel/core",
					Version:  "7.22.0",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/scoped_package.vsix", "extension/node_modules/@babel/core/package.json"),
				},
			},
		},
		{
			name:         "manifest only",
			path:         "testdata/manifest_only.vsix",
			wantPackages: []*extractor.Package{},
		},
		{
			name: "non package entries",
			path: "testdata/non_package_entries.vsix",
			wantPackages: []*extractor.Package{
				{
					Name:     "ms",
					Version:  "2.1.3",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/non_package_entries.vsix", "extension/node_modules/ms/package.json"),
				},
			},
		},
		{
			name: "malformed json mixed",
			path: "testdata/malformed_json_mixed.vsix",
			wantPackages: []*extractor.Package{
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/malformed_json_mixed.vsix", "extension/node_modules/lodash/package.json"),
				},
			},
		},
		{
			name:         "missing fields",
			path:         "testdata/missing_fields.vsix",
			wantPackages: []*extractor.Package{},
		},
		{
			name:         "empty archive",
			path:         "testdata/empty_archive.vsix",
			wantPackages: []*extractor.Package{},
		},
		{
			name:         "invalid zip",
			path:         "testdata/invalid_zip.vsix",
			wantPackages: []*extractor.Package{},
		},
		{
			name: "nested archive ignored",
			path: "testdata/nested_archive_ignored.vsix",
			wantPackages: []*extractor.Package{
				{
					Name:     "outer",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/nested_archive_ignored.vsix", "extension/node_modules/outer/package.json"),
				},
			},
		},
		{
			name: "node_modules path segment",
			path: "testdata/node_modules_substring.vsix",
			wantPackages: []*extractor.Package{
				{
					Name:     "real",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Location: pkgLoc("testdata/node_modules_substring.vsix", "extension/node_modules/real/package.json"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.path)
			if err != nil {
				t.Fatalf("os.Open(%q): %v", tt.path, err)
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("f.Stat(%q): %v", tt.path, err)
			}

			e, err := vsix.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("vsix.New: %v", err)
			}

			got, err := e.Extract(t.Context(), &filesystem.ScanInput{
				Path:   tt.path,
				Reader: f,
				Info:   info,
			})
			if err != nil {
				t.Fatalf("Extract(%q): %v", tt.path, err)
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(
				wantInv,
				got,
				cmpopts.SortSlices(func(a, b *extractor.Package) bool {
					return a.Name < b.Name
				}),
				cmpopts.EquateEmpty(),
			); diff != "" {
				t.Errorf("Extract(%q) mismatch (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}
