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

package apk_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/os/apk"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	var e extractor.InventoryExtractor = apk.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "installed file",
			path:           "lib/apk/db/installed",
			wantIsRequired: true,
		},
		{
			name:           "sub file",
			path:           "lib/apk/db/installed/test",
			wantIsRequired: false,
		},
		{
			name:           "directory",
			path:           "lib/apk/db/installed/",
			wantIsRequired: false,
		},
		{
			name:           "inside other dir",
			path:           "foo/lib/apk/db/installed/",
			wantIsRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isRequired := e.FileRequired(tt.path, 0)
			if isRequired != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantIsRequired)
			}
		})
	}
}

const alpine = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.18.0
PRETTY_NAME="Alpine Linux v3.18"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"`

func TestExtract(t *testing.T) {
	var e extractor.InventoryExtractor = apk.Extractor{}

	tests := []struct {
		name          string
		path          string
		osrelease     string
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name:      "alpine latest",
			path:      "testdata/installed",
			osrelease: alpine,
			wantInventory: []*extractor.Inventory{
				getInventory("testdata/installed", e.Name(), "alpine-baselayout", "alpine-baselayout", "3.4.3-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only"),
				getInventory("testdata/installed", e.Name(), "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only"),
				getInventory("testdata/installed", e.Name(), "alpine-keys", "alpine-keys", "2.4-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "MIT"),
				getInventory("testdata/installed", e.Name(), "apk-tools", "apk-tools", "2.14.0-r0", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only"),
				getInventory("testdata/installed", e.Name(), "busybox", "busybox", "1.36.0-r9", "alpine", "3.18.0", "Sören Tempel <soeren+alpine@soeren-tempel.net>", "x86_64", "GPL-2.0-only"),
				getInventory("testdata/installed", e.Name(), "busybox-binsh", "busybox", "1.36.0-r9", "alpine", "3.18.0", "Sören Tempel <soeren+alpine@soeren-tempel.net>", "x86_64", "GPL-2.0-only"),
				getInventory("testdata/installed", e.Name(), "ca-certificates-bundle", "ca-certificates", "20230506-r0", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "MPL-2.0 AND MIT"),
				getInventory("testdata/installed", e.Name(), "libc-utils", "libc-dev", "0.7.2-r5", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "BSD-2-Clause AND BSD-3-Clause"),
				getInventory("testdata/installed", e.Name(), "libcrypto3", "openssl", "3.1.0-r4", "alpine", "3.18.0", "Ariadne Conill <ariadne@dereferenced.org>", "x86_64", "Apache-2.0"),
				getInventory("testdata/installed", e.Name(), "libssl3", "openssl", "3.1.0-r4", "alpine", "3.18.0", "Ariadne Conill <ariadne@dereferenced.org>", "x86_64", "Apache-2.0"),
				getInventory("testdata/installed", e.Name(), "musl", "musl", "1.2.4-r0", "alpine", "3.18.0", "Timo Teräs <timo.teras@iki.fi>", "x86_64", "MIT"),
				getInventory("testdata/installed", e.Name(), "musl-utils", "musl", "1.2.4-r0", "alpine", "3.18.0", "Timo Teräs <timo.teras@iki.fi>", "x86_64", "MIT AND BSD-2-Clause AND GPL-2.0-or-later"),
				getInventory("testdata/installed", e.Name(), "scanelf", "pax-utils", "1.3.7-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only"),
				getInventory("testdata/installed", e.Name(), "ssl_client", "busybox", "1.36.0-r9", "alpine", "3.18.0", "Sören Tempel <soeren+alpine@soeren-tempel.net>", "x86_64", "GPL-2.0-only"),
				getInventory("testdata/installed", e.Name(), "zlib", "zlib", "1.2.13-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "Zlib"),
			},
		},
		{
			name:      "origin not set",
			path:      "testdata/no-origin",
			osrelease: alpine,
			wantInventory: []*extractor.Inventory{
				getInventory("testdata/no-origin", e.Name(), "pkgname", "", "1.2.3", "alpine", "3.18.0", "", "x86_64", "GPL-2.0-only"),
			},
		},
		{
			name:          "empty",
			path:          "testdata/empty",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:          "invalid",
			path:          "testdata/invalid",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "osrelease openwrt",
			path: "testdata/single",
			osrelease: `ID=openwrt
			VERSION_ID=1.2.3`,
			wantInventory: []*extractor.Inventory{
				getInventory("testdata/single", e.Name(), "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "openwrt", "1.2.3", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only"),
			},
		},
		{
			name:      "osrelease no version",
			path:      "testdata/single",
			osrelease: "ID=openwrt",
			wantInventory: []*extractor.Inventory{
				getInventory("testdata/single", e.Name(), "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "openwrt", "", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only"),
			},
		},
		{
			name:      "no osrelease",
			path:      "testdata/single",
			osrelease: "",
			wantInventory: []*extractor.Inventory{
				getInventory("testdata/single", e.Name(), "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "", "", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only"),
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

			input := &extractor.ScanInput{Path: tt.path, Reader: r, ScanRoot: d}
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
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
	e := apk.Extractor{}
	tests := []struct {
		name     string
		metadata *apk.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "all fields present",
			metadata: &apk.Metadata{
				PackageName: "Name",
				OriginName:  "originName",
				OSID:        "id",
				OSVersionID: "4.5.6",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeApk,
				Name:       "name",
				Namespace:  "id",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "4.5.6", purl.Origin: "originName"}),
			},
		},
		{
			name: "OS ID missing",
			metadata: &apk.Metadata{
				PackageName: "Name",
				OriginName:  "originName",
				OSVersionID: "4.5.6",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeApk,
				Name:       "name",
				Namespace:  "alpine",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "4.5.6", purl.Origin: "originName"}),
			},
		},
		{
			name: "OS version ID missing",
			metadata: &apk.Metadata{
				PackageName: "Name",
				OriginName:  "originName",
				OSID:        "id",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeApk,
				Name:       "name",
				Namespace:  "id",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Origin: "originName"}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      "Name",
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

func getInventory(path, ext, pkgName, origin, version, osID, osVersionID, maintainer, arch, license string) *extractor.Inventory {
	return &extractor.Inventory{
		Locations: []string{path},
		Extractor: ext,
		Name:      pkgName,
		Version:   version,
		Metadata: &apk.Metadata{
			PackageName:  pkgName,
			OriginName:   origin,
			OSID:         osID,
			OSVersionID:  osVersionID,
			Maintainer:   maintainer,
			Architecture: arch,
			License:      license,
		},
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
