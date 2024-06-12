// Copyright 2024 Google LLC
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

package cos_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/cos"
	"github.com/google/osv-scalibr/purl"
)

const (
	cosOSRlease = `NAME="Container-Optimized OS"
	ID=cos
	VERSION=101
	VERSION_ID=101`
	cosOSRleaseNoVersionID = `NAME="Container-Optimized OS"
	ID=cos
	VERSION=101`
	cosOSRleaseNoVersions = `NAME="Container-Optimized OS"
	ID=cos`
)

func TestFileRequired(t *testing.T) {
	var e filesystem.Extractor = cos.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "package info",
			path:           "etc/cos-package-info.json",
			wantIsRequired: true,
		}, {
			name:           "not a package info file",
			path:           "some/other/file.json",
			wantIsRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isRequired := e.FileRequired(tt.path, nil)
			if isRequired != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantIsRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	var e filesystem.Extractor = cos.Extractor{}

	tests := []struct {
		name          string
		path          string
		osrelease     string
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name:      "invalid",
			path:      "testdata/invalid",
			osrelease: cosOSRlease,
			wantErr:   cmpopts.AnyError,
		},
		{
			name:          "empty",
			path:          "testdata/empty.json",
			osrelease:     cosOSRlease,
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:      "single",
			path:      "testdata/single.json",
			osrelease: cosOSRlease,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "python-exec",
					Version:   "17162.336.16",
					Locations: []string{"testdata/single.json"},
					Metadata: &cos.Metadata{
						Name:        "python-exec",
						Version:     "17162.336.16",
						Category:    "dev-lang",
						OSVersion:   "101",
						OSVersionID: "101",
					},
				},
			},
		},
		{
			name:      "multiple",
			path:      "testdata/multiple.json",
			osrelease: cosOSRlease,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "python-exec",
					Version:   "17162.336.16",
					Locations: []string{"testdata/multiple.json"},
					Metadata: &cos.Metadata{
						Name:        "python-exec",
						Version:     "17162.336.16",
						Category:    "dev-lang",
						OSVersion:   "101",
						OSVersionID: "101",
					},
				},
				&extractor.Inventory{
					Name:      "zlib",
					Version:   "17162.336.17",
					Locations: []string{"testdata/multiple.json"},
					Metadata: &cos.Metadata{
						Name:        "zlib",
						Version:     "17162.336.17",
						Category:    "sys-libs",
						OSVersion:   "101",
						OSVersionID: "101",
					},
				},
				&extractor.Inventory{
					Name:      "baselayout",
					Version:   "17162.336.18",
					Locations: []string{"testdata/multiple.json"},
					Metadata: &cos.Metadata{
						Name:        "baselayout",
						Version:     "17162.336.18",
						Category:    "sys-apps",
						OSVersion:   "101",
						OSVersionID: "101",
					},
				},
				&extractor.Inventory{
					Name:      "ncurses",
					Version:   "17162.336.19",
					Locations: []string{"testdata/multiple.json"},
					Metadata: &cos.Metadata{
						Name:        "ncurses",
						Version:     "17162.336.19",
						Category:    "sys-libs",
						OSVersion:   "101",
						OSVersionID: "101",
					},
				},
			},
		},
		{
			name:      "no version ID",
			path:      "testdata/single.json",
			osrelease: cosOSRleaseNoVersionID,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "python-exec",
					Version:   "17162.336.16",
					Locations: []string{"testdata/single.json"},
					Metadata: &cos.Metadata{
						Name:      "python-exec",
						Version:   "17162.336.16",
						Category:  "dev-lang",
						OSVersion: "101",
					},
				},
			},
		},
		{
			name:      "no version or version ID",
			path:      "testdata/single.json",
			osrelease: cosOSRleaseNoVersions,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "python-exec",
					Version:   "17162.336.16",
					Locations: []string{"testdata/single.json"},
					Metadata: &cos.Metadata{
						Name:     "python-exec",
						Version:  "17162.336.16",
						Category: "dev-lang",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			input := &filesystem.ScanInput{Path: tt.path, Reader: r, ScanRoot: d}
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantErr)
			}

			ignoreOrder := cmpopts.SortSlices(func(a, b any) bool {
				return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
			})
			if diff := cmp.Diff(tt.wantInventory, got, ignoreOrder); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := cos.Extractor{}
	tests := []struct {
		name     string
		metadata *cos.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "both versions present",
			metadata: &cos.Metadata{
				OSVersionID: "101",
				OSVersion:   "97",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "name",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "cos-101"}),
			},
		},
		{
			name: "only VERSION set",
			metadata: &cos.Metadata{
				OSVersion: "97",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "name",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "cos-97"}),
			},
		},
		{
			name: "only VERSION_ID set",
			metadata: &cos.Metadata{
				OSVersionID: "101",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "name",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "cos-101"}),
			},
		},
		{
			name:     "no versions set",
			metadata: &cos.Metadata{},
			want: &purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "name",
				Version:    "1.2.3",
				Qualifiers: purl.Qualifiers{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      "name",
				Version:   "1.2.3",
				Metadata:  tt.metadata,
				Locations: []string{"location"},
			}
			got, err := e.ToPURL(i)
			if err != nil {
				t.Fatalf("ToPURL(%v): %v", i, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
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
