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

package snap_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/snap"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

const DebianBookworm = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian`

func TestFileRequired(t *testing.T) {
	// supported OSes
	if !slices.Contains([]string{"linux"}, runtime.GOOS) {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "package info",
			path:             "snap/core/current/meta/snap.yaml",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		}, {
			name:         "not a snap yaml file",
			path:         "some/other/file.yaml",
			wantRequired: false,
		}, {
			name:         "missing revision in path",
			path:         "snap/core/meta/snap.yaml",
			wantRequired: false,
		}, {
			name:         "missing name in path",
			path:         "snap/current/meta/snap.yaml",
			wantRequired: false,
		}, {
			name:         "extra dirs in path",
			path:         "snap/core/current/extra/meta/snap.yaml",
			wantRequired: false,
		}, {
			name:             "snap.yaml required if file size < max file size",
			path:             "snap/core/current/meta/snap.yaml",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		}, {
			name:             "snap.yaml required if file size == max file size",
			path:             "snap/core/current/meta/snap.yaml",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		}, {
			name:             "snap.yaml not required if file size > max file size",
			path:             "snap/core/current/meta/snap.yaml",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		}, {
			name:             "snap.yaml required if max file size set to 0",
			path:             "snap/core/current/meta/snap.yaml",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = snap.New(snap.Config{
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
	// supported OSes
	if !slices.Contains([]string{"linux"}, runtime.GOOS) {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	tests := []struct {
		name             string
		path             string
		osrelease        string
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:             "invalid",
			path:             "testdata/invalid",
			osrelease:        DebianBookworm,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:      "valid yaml with single arch",
			path:      "testdata/single-arch.yaml",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:      "core",
					Version:   "16-2.61.4-20240607",
					Locations: []string{"testdata/single-arch.yaml"},
					Metadata: &snap.Metadata{
						Name:              "core",
						Version:           "16-2.61.4-20240607",
						Grade:             "stable",
						Type:              "os",
						Architectures:     []string{"amd64"},
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "valid yaml with multiple arch",
			path:      "testdata/multi-arch.yaml",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:      "core",
					Version:   "16-2.61.4-20240607",
					Locations: []string{"testdata/multi-arch.yaml"},
					Metadata: &snap.Metadata{
						Name:              "core",
						Version:           "16-2.61.4-20240607",
						Grade:             "stable",
						Type:              "os",
						Architectures:     []string{"amd64", "arm64"},
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "yaml missing name",
			path:             "testdata/missing-name.yaml",
			osrelease:        DebianBookworm,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "yaml missing version",
			path:             "testdata/missing-version.yaml",
			osrelease:        DebianBookworm,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = snap.New(snap.Config{
				Stats: collector,
			})

			d := t.TempDir()
			createOsRelease(t, d, tt.osrelease)

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

func TestToPURL(t *testing.T) {
	snapName := "testSnap"
	snapVersion := "1.2.3"
	snapGrade := "stable"
	snapType := "os"
	architectures := []string{"amd64", "arm64"}
	osID := "debian"
	osVersionCodename := "bookworm"
	osVersionID := "12"

	e := snap.Extractor{}
	tests := []struct {
		name     string
		metadata *snap.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "Both VERSION_CODENAME and VERSION_ID are set",
			metadata: &snap.Metadata{
				Name:              snapName,
				Version:           snapVersion,
				Grade:             snapGrade,
				Type:              snapType,
				Architectures:     architectures,
				OSID:              osID,
				OSVersionCodename: osVersionCodename,
				OSVersionID:       osVersionID,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeSnap,
				Name:      snapName,
				Namespace: osID,
				Version:   snapVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: osVersionCodename,
				}),
			},
		},
		{
			name: "Only VERSION_ID is set",
			metadata: &snap.Metadata{
				Name:          snapName,
				Version:       snapVersion,
				Grade:         snapGrade,
				Type:          snapType,
				Architectures: architectures,
				OSID:          osID,
				OSVersionID:   osVersionID,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeSnap,
				Name:      snapName,
				Namespace: osID,
				Version:   snapVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: osVersionID,
				}),
			},
		},
		{
			name: "OSID, VERSION_CODENAME and VERSION_ID all are not set",
			metadata: &snap.Metadata{
				Name:          snapName,
				Version:       snapVersion,
				Grade:         snapGrade,
				Type:          snapType,
				Architectures: architectures,
			},
			want: &purl.PackageURL{
				Type:       purl.TypeSnap,
				Name:       snapName,
				Namespace:  "",
				Version:    snapVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      snapName,
				Version:   snapVersion,
				Metadata:  tt.metadata,
				Locations: []string{"location"},
			}
			got := e.ToPURL(i)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
			}
		})
	}
}

func TestEcosystem(t *testing.T) {
	e := snap.Extractor{}
	tests := []struct {
		name     string
		metadata *snap.Metadata
		want     string
	}{
		{
			name: "OS ID present",
			metadata: &snap.Metadata{
				OSID: "ubuntu",
			},
			want: "Ubuntu",
		},
		{
			name:     "OS ID not present",
			metadata: &snap.Metadata{},
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Metadata: tt.metadata,
			}
			got := e.Ecosystem(i)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Ecosystem(%v) (-want +got):\n%s", i, diff)
			}
		})
	}
}

func createOsRelease(t *testing.T, root string, content string) {
	t.Helper()
	os.MkdirAll(filepath.Join(root, "etc"), 0755)
	err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "etc/os-release"), err)
	}
}
