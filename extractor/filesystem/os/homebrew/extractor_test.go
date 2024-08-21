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

package homebrew_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	"github.com/google/osv-scalibr/purl"
)

func TestExtractableFile(t *testing.T) {
	var e filesystem.Extractor = homebrew.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "sbom.spdx.json",
			path:           "testdata/sbom.spdx.json",
			wantIsRequired: false,
		},
		{
			name:           "cellar.sbom.spdx.json",
			path:           "testdata/Cellar/sbom.spdx.json",
			wantIsRequired: true,
		},
		{
			name:           "bad.spdx.txt",
			path:           "testdata/cellar/bad.spdx.txt",
			wantIsRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.FileRequired(tt.path, nil); got != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantIsRequired)
			}
		})
	}
}

func invLess(i1, i2 *extractor.Inventory) bool {
	return i1.Name < i2.Name
}

func TestExtract(t *testing.T) {
	var e filesystem.Extractor = homebrew.Extractor{}

	tests := []struct {
		name          string
		path          string
		wantErr       error
		wantInventory []*extractor.Inventory
	}{
		{
			name: "cellar.sbom.spdx.json",
			path: "testdata/Cellar/sbom.spdx.json",
			wantInventory: []*extractor.Inventory{
				{
					Name: "rclone",
					Metadata: &homebrew.Metadata{
						PURL: getPURL("rclone", "pkg:brew/homebrew/core/rclone@1.67.0"),
					},
					Locations: []string{"testdata/Cellar/sbom.spdx.json"},
				},
			},
		},
		{
			name: "purl_and_cpe.spdx.json",
			path: "testdata/Cellar/sbom.spdx.json",
			wantInventory: []*extractor.Inventory{
				{
					Name: "rclone",
					Metadata: &homebrew.Metadata{
						PURL: getPURL("rclone", "pkg:brew/homebrew/core/rclone@1.67.0"),
					},
					Locations: []string{"testdata/Cellar/sbom.spdx.json"},
				},
			},
		},
		{
			name: "sbom.spdx",
			path: "testdata/Cellar/sbom.spdx.json",
			wantInventory: []*extractor.Inventory{
				{
					Name: "rclone",
					Metadata: &homebrew.Metadata{
						PURL: getPURL("rclone", "pkg:brew/homebrew/core/rclone@1.67.0"),
					},
					Locations: []string{"testdata/Cellar/sbom.spdx.json"},
				},
			},
		},
		{
			name:    "Caskroom.sbom.spdx.json",
			path:    "testdata/Caskroom/sbom.spdx.json",
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			r, err := os.Open(tt.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			input := &filesystem.ScanInput{Path: tt.path, Reader: r}
			got, err := e.Extract(context.Background(), input)
			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Extract(%s) unexpected error (-want +got):\n%s", tt.path, diff)
			}

			want := tt.wantInventory

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(invLess)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

// func TestToPURL(t *testing.T) {
// 	e := spdx.Extractor{}
// 	want := &purl.PackageURL{
// 		Type:      purl.TypePyPi,
// 		Name:      "name",
// 		Namespace: "namespace",
// 		Version:   "1.2.3",
// 	}
// 	i := &extractor.Inventory{
// 		Name: "name",
// 		Metadata: &spdx.Metadata{
// 			PURL: want,
// 			CPEs: []string{},
// 		},
// 		Locations: []string{"location"},
// 	}
// 	got, err := e.ToPURL(i)
// 	if err != nil {
// 		t.Fatalf("ToPURL(%v): %v", i, err)
// 	}
// 	if diff := cmp.Diff(want, got); diff != "" {
// 		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
// 	}
// }

// func TestToCPEs(t *testing.T) {
// 	e := spdx.Extractor{}
// 	want := []string{"cpe1", "cpe2"}
// 	i := &extractor.Inventory{
// 		Name: "name",
// 		Metadata: &spdx.Metadata{
// 			CPEs: want,
// 		},
// 		Locations: []string{"location"},
// 	}
// 	got, err := e.ToCPEs(i)
// 	if err != nil {
// 		t.Fatalf("ToCPEs(%v): %v", i, err)
// 	}
// 	if diff := cmp.Diff(want, got); diff != "" {
// 		t.Errorf("ToCPEs(%v) (-want +got):\n%s", i, diff)
// 	}
// }

// func invLess(i1, i2 *extractor.Inventory) bool {
// 	return i1.Name < i2.Name
// }

func getPURL(name, version string) *purl.PackageURL {
	return &purl.PackageURL{
		Type:       purl.TypeGeneric,
		Name:       name,
		Version:    version,
		Qualifiers: purl.Qualifiers{},
	}
}
