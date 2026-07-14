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

package opamfile_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ocaml/opamfile"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
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
			name:         "package .opam file",
			path:         "project/myproject.opam",
			wantRequired: true,
		},
		{
			name:         "plain opam project file",
			path:         "project/opam",
			wantRequired: true,
		},
		{
			name:             "opam file at size limit",
			path:             "project/myproject.opam",
			fileSizeBytes:    10 * units.KiB,
			maxFileSizeBytes: 10 * units.KiB,
			wantRequired:     true,
		},
		{
			name:             "opam file above size limit",
			path:             "project/myproject.opam",
			fileSizeBytes:    11 * units.KiB,
			maxFileSizeBytes: 10 * units.KiB,
			wantRequired:     false,
		},
		{
			name:         "opam switch install file is handled by ocaml/opam",
			path:         "project/.opam-switch/install",
			wantRequired: false,
		},
		{
			name:         "backup file",
			path:         "project/myproject.opam.bak",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := opamfile.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("opamfile.New(%v) error: %v", tt.maxFileSizeBytes, err)
			}

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}
			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if got != tt.wantRequired {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty",
			},
			WantPackages: nil,
		},
		{
			Name: "valid file with depends and depopts",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "dune",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "ocaml",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "astring",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "cmdliner",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "alcotest",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "lwt",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "async",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
			},
		},
		{
			Name: "edge cases with constraints and comments",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/edge",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cppo",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "dune",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "ocaml",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "ocamlfind",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "odoc",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "dune-configurator",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "base-threads",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "base-unix",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
			},
		},
		{
			Name: "opam 1.2 single string depends",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/opam12_single",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ocamlfind",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/opam12_single"),
				},
			},
		},
		{
			Name: "comments are ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/comments",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "dune",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/comments"),
				},
				{
					Name:     "ocamlfind",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/comments"),
				},
				{
					Name:     "alcotest",
					Version:  "",
					PURLType: purl.TypeOpam,
					Location: extractor.LocationFromPath("testdata/comments"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := opamfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("opamfile.New: %v", err)
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
