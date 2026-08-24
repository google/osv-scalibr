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

package poetrylock_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
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
		{
			name:      "",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "poetry.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/poetry.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/poetry.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/poetry.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.poetry.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := poetrylock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("poetrylock.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

// testIDGenerator produces IDs unique across duplicate package names, unlike
// mockidgenerator, and resettable per subtest, unlike SequentialIDGenerator.
type testIDGenerator struct{ counter int }

func (g *testIDGenerator) GenerateID(name string) (string, error) {
	g.counter++
	return fmt.Sprintf("id-%s-%d", name, g.counter), nil
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty-file.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
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
					Name:     "numpy",
					ID:       "id-numpy-1",
					Version:  "1.23.3",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/one-package.lock", 2),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "proto-plus",
					ID:       "id-proto-plus-1",
					Version:  "1.22.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages.lock", 2),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "protobuf",
					ID:        "id-protobuf-2",
					ParentIDs: map[string]bool{"id-proto-plus-1": true},
					Version:   "4.21.5",
					PURLType:  purl.TypePyPi,
					Location:  extractor.LocationFromPathAndLine("testdata/two-packages.lock", 16),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with metadata",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-with-metadata.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "emoji",
					ID:       "id-emoji-1",
					Version:  "2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/one-package-with-metadata.lock", 2),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with git source",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-git.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ike",
					ID:       "id-ike-1",
					Version:  "0.2.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/source-git.lock", 2),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "cd66602cd29f61a2d2e7fb995fef1e61708c034d",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with legacy source",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-legacy.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "appdirs",
					ID:       "id-appdirs-1",
					Version:  "1.4.4",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/source-legacy.lock", 2),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "optional package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/optional-package.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "numpy",
					ID:       "id-numpy-1",
					Version:  "1.23.3",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/optional-package.lock", 2),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
		{
			Name: "multiple packages with a v2 lockfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-packages.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "async-timeout",
					ID:        "id-async-timeout-1",
					ParentIDs: map[string]bool{"id-redis-8": true},
					Version:   "5.0.1",
					PURLType:  purl.TypePyPi,
					Location:  extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 4),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
				{
					Name:     "factory-boy",
					ID:       "id-factory-boy-2",
					Version:  "3.3.1",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 17),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "faker",
					ID:        "id-faker-3",
					ParentIDs: map[string]bool{"id-factory-boy-2": true},
					Version:   "33.3.0",
					PURLType:  purl.TypePyPi,
					Location:  extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 36),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev", "test"},
					},
				},
				{
					Name:     "proto-plus",
					ID:       "id-proto-plus-4",
					Version:  "1.22.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 52),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "proto-plus",
					ID:       "id-proto-plus-5",
					Version:  "1.23.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 71),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "protobuf",
					ID:        "id-protobuf-6",
					ParentIDs: map[string]bool{"id-proto-plus-4": true, "id-proto-plus-5": true},
					Version:   "4.25.5",
					PURLType:  purl.TypePyPi,
					Location:  extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 90),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "python-dateutil",
					ID:        "id-python-dateutil-7",
					ParentIDs: map[string]bool{"id-faker-3": true},
					Version:   "2.9.0.post0",
					PURLType:  purl.TypePyPi,
					Location:  extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 111),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev", "test"},
					},
				},
				{
					Name:      "six",
					ID:        "id-six-9",
					ParentIDs: map[string]bool{"id-python-dateutil-7": true},
					Version:   "1.17.0",
					PURLType:  purl.TypePyPi,
					Location:  extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 146),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "typing-extensions",
					ID:        "id-typing-extensions-10",
					ParentIDs: map[string]bool{"id-faker-3": true},
					Version:   "4.12.2",
					PURLType:  purl.TypePyPi,
					Location:  extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 158),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev", "test"},
					},
				},
				{
					Name:     "urllib3",
					ID:       "id-urllib3-11",
					Version:  "2.3.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 170),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "redis",
					ID:       "id-redis-8",
					Version:  "5.2.1",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-packages.v2.lock", 126),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
		{
			Name: "names outside package block",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/names-outside-package-block.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "first-pkg",
					ID:       "id-first-pkg-1",
					Version:  "1.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/names-outside-package-block.lock", 5),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "second-pkg",
					ID:       "id-second-pkg-2",
					Version:  "2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/names-outside-package-block.lock", 18),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extractor.SetIDGenerator(&testIDGenerator{})
			t.Cleanup(func() { extractor.SetIDGenerator(&extractor.RandomIDGenerator{}) })

			extr, err := poetrylock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("poetrylock.New: %v", err)
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
