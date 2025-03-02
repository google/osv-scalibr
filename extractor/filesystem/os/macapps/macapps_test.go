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

package macapps_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/macapps"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

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
			name:             "Valid_File_Path_for_Info.plist",
			path:             "Applications/GoogleChrome.app/Contents/Info.plist",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "Invalid_Prefix_for_Info.plist",
			path:         "/testdata/Applications/GoogleChrome.app/Contents/Info.plist",
			wantRequired: false,
		},
		{
			name:         "Invalid_Suffix_for_Info.plist",
			path:         "Applications/GoogleChrome.app/Contents/Info.plists",
			wantRequired: false,
		},
		{
			name:         "InvalidMiddle_for_Info.plist",
			path:         "Applications/GoogleChrome.app/Info.plist",
			wantRequired: false,
		},
		{
			name:         "no_sub_packages",
			path:         "Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/Info.plist",
			wantRequired: false,
		},
		{
			name:             "Info.plist_file_required_if_file_size<max_file_size",
			path:             "Applications/LargeApp/Contents/Info.plist",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Info.plist_file_required_if_file_size==max_file_size",
			path:             "Applications/LargeApp/Contents/Info.plist",
			fileSizeBytes:    1 * units.MiB,
			maxFileSizeBytes: 1 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Info.plist_file_not_required_if_file_size>max_file_size",
			path:             "Applications/LargeApp/Contents/Info.plist",
			fileSizeBytes:    10 * units.MiB,
			maxFileSizeBytes: 1 * units.MiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e := macapps.New(macapps.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

			// Set a default file size if not specified.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "Valid_XML_Info.plist_data ",
			path: "testdata/ValidXML.plist",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "Chrome",
					Version:   "130.0.6723.69",
					Locations: []string{"testdata/ValidXML.plist"},
					Metadata: &macapps.Metadata{
						CFBundleDisplayName:        "Google Chrome",
						CFBundleIdentifier:         "com.google.Chrome",
						CFBundleShortVersionString: "130.0.6723.69",
						CFBundleExecutable:         "Google Chrome",
						CFBundleName:               "Chrome",
						CFBundlePackageType:        "APPL",
						CFBundleSignature:          "rimZ",
						CFBundleVersion:            "6723.69",
						KSProductID:                "com.google.Chrome",
						KSUpdateURL:                "https://tools.google.com/service/update2",
					},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "Valid_Binary_Info.plist_data ",
			path: "testdata/BinaryApp.plist",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "gMacInformation",
					Version:   "202410231131",
					Locations: []string{"testdata/BinaryApp.plist"},
					Metadata: &macapps.Metadata{
						CFBundleDisplayName:        "",
						CFBundleIdentifier:         "com.google.corp.gMacInformation",
						CFBundleShortVersionString: "202410231131",
						CFBundleExecutable:         "gMacInformation",
						CFBundleName:               "gMacInformation",
						CFBundlePackageType:        "APPL",
						CFBundleSignature:          "????",
						CFBundleVersion:            "202410231131",
						KSProductID:                "",
						KSUpdateURL:                "",
					},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "Empty_Info.plist_data ",
			path:             "testdata/Empty.plist",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "Invalid_format_Info.plist_data ",
			path:             "testdata/InvalidFormat.plist",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "Missing_Info.plist_data ",
			path: "testdata/MissingData.plist",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "Chrome",
					Version:   "",
					Locations: []string{"testdata/MissingData.plist"},
					Metadata: &macapps.Metadata{
						CFBundleDisplayName:        "",
						CFBundleIdentifier:         "com.google.Chrome",
						CFBundleShortVersionString: "",
						CFBundleExecutable:         "Google Chrome",
						CFBundleName:               "Chrome",
						CFBundlePackageType:        "APPL",
						CFBundleSignature:          "rimZ",
						CFBundleVersion:            "6723.69",
						KSProductID:                "com.google.Chrome",
						KSUpdateURL:                "https://tools.google.com/service/update2",
					},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "Different_Format_Info.plist_data ",
			path:             "testdata/DifferentFormat.plist",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e := macapps.New(macapps.Config{
				Stats: collector,
			})

			d := t.TempDir()

			r, err := os.Open(tt.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatalf("Failed to stat test file: %v", err)
			}

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS(d),
				Path:   tt.path,
				Reader: r,
				Root:   d,
				Info:   info,
			}

			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantErr)
			}

			ignoreOrder := cmpopts.SortSlices(func(a, b any) bool {
				return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
			})
			if diff := cmp.Diff(tt.wantInventory, got, ignoreOrder); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}
