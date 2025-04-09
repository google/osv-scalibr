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

package vscodeextensions_test

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/vscodeextensions"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
		separator rune
	}{
		{
			inputPath: "", want: false,
		},
		{
			inputPath: "/home/username/.vscode/extensions/extensions.json", want: true,
		},
		{
			inputPath: "/home/username/.vscode/extensions/bad.json", want: false,
		},
		{
			inputPath: "/home/username/.vscode/extensions/bad.json", want: false,
		},
		{
			inputPath: "/home/username/.vscode/extensions/bad.json", want: false,
		},
		{
			inputPath: "C:\\Users\\username\\.vscode\\extensions\\bad.json", want: false,
			separator: '\\',
		},
		{
			inputPath: "C:\\Users\\username\\.vscode\\extensions\\extensions.json", want: true,
			separator: '\\',
		},
		{
			inputPath: "/home/username/.vscode/extensions/extensions/badjson", want: false,
		},
		{
			inputPath: "/home/username/.vscode/extensions/bad/extensions.json", want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			if tt.separator == 0 {
				tt.separator = '/'
			}

			if !os.IsPathSeparator(uint8(tt.separator)) {
				t.Skipf("Skipping test on %s", runtime.GOOS)
			}

			e := vscodeextensions.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "one extension",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-extension.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:    "ms-vscode.cpptools",
					Version: "1.23.6",
					Locations: []string{
						"/home/username/.vscode/extensions/ms-vscode.cpptools-1.23.6-linux-arm64",
						"testdata/one-extension.json",
					},
					Metadata: &vscodeextensions.Metadata{
						ID:                   "690b692e-e8a9-493f-b802-8089d50ac1b2",
						PublisherID:          "5f5636e7-69ed-4afe-b5d6-8d231fb3d3ee",
						PublisherDisplayName: "Microsoft",
						TargetPlatform:       "linux-arm64",
						InstalledTimestamp:   1741171252441,
					},
				},
			},
		},
		{
			Name: "extensions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/extensions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "golang.go",
					Version:   "0.46.1",
					Locations: []string{"/home/username/.vscode/extensions/golang.go-0.46.1", "testdata/extensions.json"},
					Metadata: &vscodeextensions.Metadata{
						ID:                   "d6f6cfea-4b6f-41f4-b571-6ad2ab7918da",
						PublisherID:          "dbf6ae0a-da75-4167-ac8b-75b4512f2153",
						PublisherDisplayName: "Go Team at Google",
						TargetPlatform:       "undefined",
						InstalledTimestamp:   1741172422528,
					},
				},
				{
					Name:    "google.geminicodeassist",
					Version: "2.28.0",
					Locations: []string{
						"/home/username/.vscode/extensions/google.geminicodeassist-2.28.0",
						"testdata/extensions.json",
					},
					Metadata: &vscodeextensions.Metadata{
						ID:                   "51643712-2cb2-4384-b7cc-d55b01b8274b",
						PublisherID:          "93a45bde-b507-401c-9deb-7a098ebcded8",
						PublisherDisplayName: "Google",
						TargetPlatform:       "undefined",
						InstalledTimestamp:   1741172541483,
					},
				},
				{
					Name:    "googlecloudtools.cloudcode",
					Version: "2.27.0",
					Locations: []string{
						"/home/username/.vscode/extensions/googlecloudtools.cloudcode-2.27.0",
						"testdata/extensions.json",
					},
					Metadata: &vscodeextensions.Metadata{
						ID:                   "5e8803a2-3dc8-42b3-9c5f-ea9d37828c03",
						PublisherID:          "f24fd523-af08-49d8-bb0b-f4eda502706e",
						PublisherDisplayName: "Google Cloud",
						TargetPlatform:       "undefined",
						InstalledTimestamp:   1741172563601,
					},
				},
				{
					Name:    "ms-vscode.cpptools",
					Version: "1.23.6",
					Locations: []string{
						"/home/username/.vscode/extensions/ms-vscode.cpptools-1.23.6-linux-arm64",
						"testdata/extensions.json",
					},
					Metadata: &vscodeextensions.Metadata{
						ID:                   "690b692e-e8a9-493f-b802-8089d50ac1b2",
						PublisherID:          "5f5636e7-69ed-4afe-b5d6-8d231fb3d3ee",
						PublisherDisplayName: "Microsoft",
						TargetPlatform:       "linux-arm64",
						InstalledTimestamp:   1741171252441,
					},
				},
			},
		},
		{
			Name: "extensions on windows",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/extensions-windows.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:    "ms-python.debugpy",
					Version: "2025.4.0",
					Locations: []string{
						"/c:/Users/username/.vscode/extensions/ms-python.debugpy-2025.4.0-win32-arm64",
						"testdata/extensions-windows.json",
					},
					Metadata: &vscodeextensions.Metadata{
						ID:                   "4bd5d2c9-9d65-401a-b0b2-7498d9f17615",
						PublisherID:          "998b010b-e2af-44a5-a6cd-0b5fd3b9b6f8",
						PublisherDisplayName: "Microsoft",
						TargetPlatform:       "win32-arm64",
						InstalledTimestamp:   1741259706875,
					},
				},
				{
					Name:    "ms-python.python",
					Version: "2025.2.0",
					Locations: []string{
						"/c:/Users/username/.vscode/extensions/ms-python.python-2025.2.0-win32-arm64",
						"testdata/extensions-windows.json",
					},
					Metadata: &vscodeextensions.Metadata{
						ID:                   "f1f59ae4-9318-4f3c-a9b5-81b2eaa5f8a5",
						PublisherID:          "998b010b-e2af-44a5-a6cd-0b5fd3b9b6f8",
						PublisherDisplayName: "Microsoft",
						TargetPlatform:       "win32-arm64",
						InstalledTimestamp:   1741259706874,
					},
				},
				{
					Name:    "ms-vscode.cpptools",
					Version: "1.23.6",
					Locations: []string{
						"/c:/Users/username/.vscode/extensions/ms-vscode.cpptools-1.23.6-win32-arm64",
						"testdata/extensions-windows.json",
					},
					Metadata: &vscodeextensions.Metadata{
						ID:                   "690b692e-e8a9-493f-b802-8089d50ac1b2",
						PublisherID:          "5f5636e7-69ed-4afe-b5d6-8d231fb3d3ee",
						PublisherDisplayName: "Microsoft",
						TargetPlatform:       "win32-arm64",
						InstalledTimestamp:   1741259863413,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := vscodeextensions.New()

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			want := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
