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

package dpkg_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/os/dpkg"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	var e extractor.InventoryExtractor = dpkg.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "status file",
			path:           "var/lib/dpkg/status",
			wantIsRequired: true,
		},
		{
			name:           "file in status.d",
			path:           "var/lib/dpkg/status.d/foo",
			wantIsRequired: true,
		}, {
			name:           "status.d as a file",
			path:           "var/lib/dpkg/status.d",
			wantIsRequired: false,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			isRequired := e.FileRequired(tt.path, 0)
			if isRequired != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantIsRequired)
			}
		})
	}
}

const DebianBookworm = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian`

func TestExtract(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		osrelease     string
		cfg           dpkg.Config
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name:      "valid status file",
			path:      "testdata/valid",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "accountsservice",
					Version: "22.08.8-6",
					Metadata: &dpkg.Metadata{
						PackageName:       "accountsservice",
						PackageVersion:    "22.08.8-6",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Debian freedesktop.org maintainers <pkg-freedesktop-maintainers@lists.alioth.debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/valid"},
					Extractor: dpkg.Name,
				},
				&extractor.Inventory{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "acl",
						PackageVersion:    "2.3.1-3",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/valid"},
					Extractor: dpkg.Name,
				},
				&extractor.Inventory{
					Name:    "adduser",
					Version: "3.131",
					Metadata: &dpkg.Metadata{
						PackageName:       "adduser",
						PackageVersion:    "3.131",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Debian Adduser Developers <adduser@packages.debian.org>",
						Architecture:      "all",
					},
					Locations: []string{"testdata/valid"},
					Extractor: dpkg.Name,
				},
				&extractor.Inventory{
					Name:    "admin-session",
					Version: "2023.06.26.c543406313-00",
					Metadata: &dpkg.Metadata{
						PackageName:       "admin-session",
						PackageVersion:    "2023.06.26.c543406313-00",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "nobody@google.com",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/valid"},
					Extractor: dpkg.Name,
				},
				&extractor.Inventory{
					Name:    "attr",
					Version: "1:2.5.1-4",
					Metadata: &dpkg.Metadata{
						PackageName:       "attr",
						PackageVersion:    "1:2.5.1-4",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/valid"},
					Extractor: dpkg.Name,
				},
				// Expect source name.
				&extractor.Inventory{
					Name:    "libacl1",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "libacl1",
						PackageVersion:    "2.3.1-3",
						SourceName:        "acl",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/valid"},
					Extractor: dpkg.Name,
				},
				// Expect source name and version.
				&extractor.Inventory{
					Name:    "util-linux-extra",
					Version: "2.38.1-5+b1",
					Metadata: &dpkg.Metadata{
						PackageName:       "util-linux-extra",
						PackageVersion:    "2.38.1-5+b1",
						SourceName:        "util-linux",
						SourceVersion:     "2.38.1-5",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "util-linux packagers <util-linux@packages.debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/valid"},
					Extractor: dpkg.Name,
				},
			},
		},
		{
			name:      "packages with no version set are skipped",
			path:      "testdata/noversion",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "foo",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "foo",
						PackageVersion:    "1.0",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/noversion"},
					Extractor: dpkg.Name,
				},
				&extractor.Inventory{
					Name:    "bar",
					Version: "2.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "bar",
						PackageVersion:    "2.0",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/noversion"},
					Extractor: dpkg.Name,
				},
			},
		},
		{
			name:      "packages with no name set are skipped",
			path:      "testdata/nopackage",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "foo",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "foo",
						PackageVersion:    "1.0",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/nopackage"},
					Extractor: dpkg.Name,
				},
				&extractor.Inventory{
					Name:    "bar",
					Version: "2.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "bar",
						PackageVersion:    "2.0",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/nopackage"},
					Extractor: dpkg.Name,
				},
			},
		},
		{
			name:      "statusfield",
			path:      "testdata/statusfield",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "wantinstall_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantinstall_installed",
						PackageVersion:    "1.0",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/statusfield"},
					Extractor: dpkg.Name,
				},
				&extractor.Inventory{
					Name:    "wantdeinstall_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantdeinstall_installed",
						PackageVersion:    "1.0",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/statusfield"},
					Extractor: dpkg.Name,
				},
				&extractor.Inventory{
					Name:    "wantpurge_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantpurge_installed",
						PackageVersion:    "1.0",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/statusfield"},
					Extractor: dpkg.Name,
				},
			},
		},
		{
			name:          "empty",
			path:          "testdata/empty",
			osrelease:     DebianBookworm,
			wantInventory: []*extractor.Inventory{},
			wantErr:       cmpopts.AnyError,
		},
		{
			name:          "invalid",
			path:          "testdata/invalid",
			osrelease:     DebianBookworm,
			wantInventory: []*extractor.Inventory{},
			wantErr:       cmpopts.AnyError,
		},
		{
			name: "VERSION_CODENAME not set, fallback to VERSION_ID",
			path: "testdata/single",
			osrelease: `VERSION_ID="12"
			ID=debian`,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:    "acl",
						PackageVersion: "2.3.1-3",
						OSID:           "debian",
						OSVersionID:    "12",
						Maintainer:     "Guillem Jover <guillem@debian.org>",
						Architecture:   "amd64",
					},
					Locations: []string{"testdata/single"},
					Extractor: dpkg.Name,
				},
			},
		},
		{
			name:      "no version",
			path:      "testdata/single",
			osrelease: `ID=debian`,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:    "acl",
						PackageVersion: "2.3.1-3",
						OSID:           "debian",
						Maintainer:     "Guillem Jover <guillem@debian.org>",
						Architecture:   "amd64",
					},
					Locations: []string{"testdata/single"},
					Extractor: dpkg.Name,
				},
			},
		},
		{
			name:      "osrelease id not set",
			path:      "testdata/single",
			osrelease: "VERSION_CODENAME=bookworm",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "acl",
						PackageVersion:    "2.3.1-3",
						OSVersionCodename: "bookworm",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/single"},
					Extractor: dpkg.Name,
				},
			},
		},
		{
			name: "ubuntu",
			path: "testdata/single",
			osrelease: `VERSION_ID="22.04"
			VERSION_CODENAME=jammy
			ID=ubuntu
			ID_LIKE=debian`,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "acl",
						PackageVersion:    "2.3.1-3",
						OSID:              "ubuntu",
						OSVersionCodename: "jammy",
						OSVersionID:       "22.04",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/single"},
					Extractor: dpkg.Name,
				},
			},
		},
		{
			name:      "file size over limit",
			path:      "testdata/valid",
			osrelease: DebianBookworm,
			cfg: dpkg.Config{
				MaxFileSize: 5,
			},
			wantErr: cmpopts.AnyError,
		},
		{
			name:      "status.d file without Status field set should work",
			path:      "testdata/status.d/foo",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "foo",
					Version: "1.2.3",
					Metadata: &dpkg.Metadata{
						PackageName:       "foo",
						PackageVersion:    "1.2.3",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "someone",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/status.d/foo"},
					Extractor: dpkg.Name,
				},
			},
		},
	}

	for _, tt := range tests {
		// Note the subtest here
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

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatal(err)
			}

			input := &extractor.ScanInput{Path: tt.path, Reader: r, ScanRoot: d, Info: info}
			e := dpkg.New(defaultConfigWith(tt.cfg))
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

func TestExtractNonexistentOSRelease(t *testing.T) {
	path := "testdata/single"
	want := []*extractor.Inventory{
		&extractor.Inventory{
			Name:    "acl",
			Version: "2.3.1-3",
			Metadata: &dpkg.Metadata{
				PackageName:    "acl",
				PackageVersion: "2.3.1-3",
				OSID:           "",
				OSVersionID:    "",
				Maintainer:     "Guillem Jover <guillem@debian.org>",
				Architecture:   "amd64",
			},
			Locations: []string{path},
			Extractor: dpkg.Name,
		},
	}

	r, err := os.Open(path)
	defer func() {
		if err = r.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Note that we didn't create any OS release file.
	input := &extractor.ScanInput{Path: path, Info: info, Reader: r}

	e := dpkg.New(dpkg.DefaultConfig())
	got, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract(%s) error: %v", path, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Extract(%s) (-want +got):\n%s", path, diff)
	}
}

func TestToPURL(t *testing.T) {
	pkgname := "pkgname"
	sourcename := "sourcename"
	version := "1.2.3"
	source := "sourcename"
	e := dpkg.Extractor{}
	tests := []struct {
		name     string
		metadata *dpkg.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "both versions present",
			metadata: &dpkg.Metadata{
				PackageName:       pkgname,
				SourceName:        sourcename,
				OSID:              "debian",
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "debian",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source: source,
					purl.Distro: "jammy",
				}),
			},
		},
		{
			name: "only VERSION_ID set",
			metadata: &dpkg.Metadata{
				PackageName: pkgname,
				SourceName:  sourcename,
				OSID:        "debian",
				OSVersionID: "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "debian",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source: source,
					purl.Distro: "22.04",
				}),
			},
		},
		{
			name: "ID not set, fallback to linux",
			metadata: &dpkg.Metadata{
				PackageName:       pkgname,
				SourceName:        sourcename,
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source: source,
					purl.Distro: "jammy",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      pkgname,
				Version:   version,
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

// defaultConfigWith combines any non-zero fields of cfg with packagejson.DefaultConfig().
func defaultConfigWith(cfg dpkg.Config) dpkg.Config {
	newCfg := dpkg.DefaultConfig()

	if cfg.MaxFileSize > 0 {
		newCfg.MaxFileSize = cfg.MaxFileSize
	}
	return newCfg
}
