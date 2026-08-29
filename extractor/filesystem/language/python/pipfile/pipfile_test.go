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

package pipfile_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfile"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
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
		{name: "", inputPath: "", want: false},
		{name: "", inputPath: "Pipfile", want: true},
		{name: "", inputPath: "path/to/Pipfile", want: true},
		{name: "", inputPath: "Pipfile.lock", want: false},
		{name: "", inputPath: "pipfile", want: false},
		{name: "", inputPath: "path/to/Pipfile/file", want: false},
		{name: "", inputPath: "path/to/Pipfile.txt", want: false},
		{name: "", inputPath: "path.to.Pipfile", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := pipfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pipfile.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed.Pipfile",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.Pipfile",
			},
			WantPackages: nil,
		},
		{
			Name: "no dependency sections",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-sections.Pipfile",
			},
			WantPackages: nil,
		},
		{
			Name: "basic string specs",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic.Pipfile",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "flask",
					Version:  "2.0.1",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.Pipfile", 7),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "requests",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.Pipfile", 8),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "numpy",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.Pipfile", 9),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "urllib3",
					Version:  "1.26",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.Pipfile", 10),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "pytest",
					Version:  "7.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.Pipfile", 13),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"dev"}},
				},
				{
					Name:     "mypy",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.Pipfile", 14),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"dev"}},
				},
			},
		},
		{
			Name: "table-form entries",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/table-entries.Pipfile",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "django",
					Version:  "3.2",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/table-entries.Pipfile", 7),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "sentry-sdk",
					Version:  "1.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/table-entries.Pipfile", 8),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "celery",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/table-entries.Pipfile", 9),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "black",
					Version:  "22.3.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/table-entries.Pipfile", 12),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"dev"}},
				},
			},
		},
		{
			Name: "unsupported entries skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/unsupported-entries.Pipfile",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "flask",
					Version:  "2.0.1",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/unsupported-entries.Pipfile", 7),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "git-pkg-version",
					Version:  "1.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/unsupported-entries.Pipfile", 10),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := pipfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pipfile.New: %v", err)
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
