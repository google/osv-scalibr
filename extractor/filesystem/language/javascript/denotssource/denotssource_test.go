// Copyright 2025 Google LLC
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

package denotssource_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denometadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denotssource"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
	}{
		{
			name:         "TypeScript file .ts",
			path:         "test.ts",
			wantRequired: true,
		},
		{
			name:         "TypeScript file .tsx",
			path:         "test.tsx",
			wantRequired: true,
		},
		{
			name:         "TypeScript file .mts",
			path:         "test.mts",
			wantRequired: true,
		},
		{
			name:         "TypeScript file .cts",
			path:         "test.cts",
			wantRequired: true,
		},
		{
			name:         "TypeScript declaration file .d.ts",
			path:         "test.d.ts",
			wantRequired: true,
		},
		{
			name:         "not a TypeScript file",
			path:         "test.js",
			wantRequired: false,
		},
		{
			name:         "deno.json not required",
			path:         "deno.json",
			wantRequired: false,
		},
		{
			name:             "TypeScript file required if size less than maxFileSizeBytes",
			path:             "test.ts",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 2000 * units.MiB,
			wantRequired:     true,
		},
		{
			name:             "TypeScript file required if size equal to maxFileSizeBytes",
			path:             "test.ts",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     true,
		},
		{
			name:             "TypeScript file not required if size greater than maxFileSizeBytes",
			path:             "test.ts",
			fileSizeBytes:    10000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     false,
		},
		{
			name:             "TypeScript file required if maxFileSizeBytes explicitly set to 0",
			path:             "test.ts",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := denotssource.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("denotssource.New: %v", err)
			}
			// Set a default file size if not specified.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1 * units.KiB
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "TypeScript file contains direct package imports",
			path: "testdata/importSpecifiers.ts",
			wantPackages: []*extractor.Package{
				{
					Name:      "lodash-es",
					Version:   "4.17.22",
					Locations: []string{"testdata/importSpecifiers.ts"},
					PURLType:  purl.TypeNPM,
					Metadata: &denometadata.DenoMetadata{
						FromUnpkgCDN: true,
						URL:          "https://unpkg.com/lodash-es@4.17.22/lodash.js",
					},
				},
				{
					Name:      "lodash-es",
					Version:   "4.17.21",
					Locations: []string{"testdata/importSpecifiers.ts"},
					PURLType:  purl.TypeNPM,
					Metadata: &denometadata.DenoMetadata{
						FromUnpkgCDN: true,
						URL:          "https://unpkg.com/lodash-es@4.17.21/lodash.js",
					},
				},
				{
					Name:      "canvas-confetti",
					Version:   "1.6.0",
					PURLType:  purl.TypeNPM,
					Locations: []string{"testdata/importSpecifiers.ts"},
					Metadata: &denometadata.DenoMetadata{
						FromESMCDN: true,
						URL:        "https://esm.sh/canvas-confetti@1.6.0",
					},
				},
				{
					Name:      "openai",
					Version:   "4.69.0",
					Locations: []string{"testdata/importSpecifiers.ts"},
					PURLType:  purl.TypeNPM,
					Metadata: &denometadata.DenoMetadata{
						FromDenolandCDN: true,
						URL:             "https://deno.land/x/openai@v4.69.0/mod.ts",
					},
				},
				{
					Name:      "luca/cases",
					Version:   "1.0.0",
					Locations: []string{"testdata/importSpecifiers.ts"},
					PURLType:  purl.TypeJSR,
					Metadata: &denometadata.DenoMetadata{
						URL: "jsr:@luca/cases@1.0.0",
					},
				},
				{
					Name:      "cowsay",
					Version:   "1.6.0",
					Locations: []string{"testdata/importSpecifiers.ts"},
					PURLType:  purl.TypeNPM,
					Metadata: &denometadata.DenoMetadata{
						URL: "npm:cowsay@1.6.0",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInput := extracttest.GenerateScanInputMock(t,
				extracttest.ScanInputMockConfig{
					Path: tt.path,
				})
			e, err := denotssource.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("denotssource.New: %v", err)
			}
			got, err := e.Extract(t.Context(), &scanInput)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			var want inventory.Inventory
			if tt.wantPackages != nil {
				want = inventory.Inventory{Packages: tt.wantPackages}
			}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

func TestExtractDenoConfigAncestorCheck(t *testing.T) {
	cowsayTSContent := []byte(`import { cowsay } from "npm:cowsay@1.6.0";`)

	tests := []struct {
		name         string
		setup        func(t *testing.T) (rootDir string, tsRelPath string)
		wantPackages []*extractor.Package
	}{
		{
			name: "no deno.json or deno.lock returns empty inventory",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmpDir := t.TempDir()
				subDir := filepath.Join(tmpDir, "src")
				if err := os.MkdirAll(subDir, 0755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				if err := os.WriteFile(filepath.Join(subDir, "main.ts"), cowsayTSContent, 0644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return tmpDir, "src/main.ts"
			},
			wantPackages: nil,
		},
		{
			name: "deno.lock in parent directory finds packages",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmpDir := t.TempDir()
				subDir := filepath.Join(tmpDir, "src")
				if err := os.MkdirAll(subDir, 0755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tmpDir, "deno.lock"), []byte(`{}`), 0644); err != nil {
					t.Fatalf("WriteFile deno.lock: %v", err)
				}
				if err := os.WriteFile(filepath.Join(subDir, "main.ts"), cowsayTSContent, 0644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return tmpDir, "src/main.ts"
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "cowsay",
					Version:   "1.6.0",
					Locations: []string{"src/main.ts"},
					PURLType:  purl.TypeNPM,
					Metadata:  &denometadata.DenoMetadata{URL: "npm:cowsay@1.6.0"},
				},
			},
		},
		{
			name: "deno.json in same directory finds packages",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmpDir := t.TempDir()
				if err := os.WriteFile(filepath.Join(tmpDir, "deno.json"), []byte(`{"name": "test", "version": "1.0.0"}`), 0644); err != nil {
					t.Fatalf("WriteFile deno.json: %v", err)
				}
				if err := os.WriteFile(filepath.Join(tmpDir, "main.ts"), cowsayTSContent, 0644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return tmpDir, "main.ts"
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "cowsay",
					Version:   "1.6.0",
					Locations: []string{"main.ts"},
					PURLType:  purl.TypeNPM,
					Metadata:  &denometadata.DenoMetadata{URL: "npm:cowsay@1.6.0"},
				},
			},
		},
		{
			name: "deno.json beyond max search depth returns empty inventory",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmpDir := t.TempDir()
				deepDir := filepath.Join(tmpDir, "a", "b", "c")
				if err := os.MkdirAll(deepDir, 0755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				// deno.json at root, 3 levels up from a/b/c/ — beyond default depth of 2
				if err := os.WriteFile(filepath.Join(tmpDir, "deno.json"), []byte(`{"name": "test", "version": "1.0.0"}`), 0644); err != nil {
					t.Fatalf("WriteFile deno.json: %v", err)
				}
				if err := os.WriteFile(filepath.Join(deepDir, "main.ts"), cowsayTSContent, 0644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return tmpDir, "a/b/c/main.ts"
			},
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootDir, tsRelPath := tt.setup(t)

			f, err := os.Open(filepath.Join(rootDir, tsRelPath))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}

			e, err := denotssource.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("denotssource.New: %v", err)
			}

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS(rootDir),
				Path:   tsRelPath,
				Root:   rootDir,
				Reader: f,
				Info:   info,
			}

			got, err := e.Extract(t.Context(), input)
			if err != nil {
				t.Fatalf("Extract error: %v", err)
			}

			var want inventory.Inventory
			if tt.wantPackages != nil {
				want = inventory.Inventory{Packages: tt.wantPackages}
			}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}
