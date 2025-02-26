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

package nix_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/nix"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
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
			name:             "nix/store directory",
			path:             "nix/store/xakcaxsqdzjszym0vji2r8n0wdy2inqc-perl5.38.2-FCGI-ProcManager-0.28/xxx",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "invalid nix/store directory",
			path:         "nix/xxx/xakcaxsqdzjszym0vji2r8n0wdy2inqc-perl5.38.2-FCGI-ProcManager-0.28/xxx",
			wantRequired: false,
		},
		{
			name:         "invalid nix/store directory",
			path:         "nix/storefoo/sss",
			wantRequired: false,
		},
		{
			name:         "nix/store directory already parsed",
			path:         "nix/store/xakcaxsqdzjszym0vji2r8n0wdy2inqc-perl5.38.2-FCGI-ProcManager-0.28/sss",
			wantRequired: false,
		},
		{
			name:         "no nix/store prefix",
			path:         "foo/store/xakcaxsqdzjszym0vji2r8n0wdy2inqc-perl5.38.2-FCGI-ProcManager-0.28/sss",
			wantRequired: false,
		},
	}

	var e filesystem.Extractor = nix.New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
			}))

			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	const NixVicuna = `ANSI_COLOR="1;34"
	BUG_REPORT_URL="https://github.com/NixOS/nixpkgs/issues"
	BUILD_ID="24.11.710315.b681065d0919"
	CPE_NAME="cpe:/o:nixos:nixos:24.11"
	DEFAULT_HOSTNAME=nixos
	DOCUMENTATION_URL="https://nixos.org/learn.html"
	HOME_URL="https://nixos.org/"
	ID=nixos
	ID_LIKE=""
	IMAGE_ID=""
	IMAGE_VERSION=""
	LOGO="nix-snowflake"
	NAME=NixOS
	PRETTY_NAME="NixOS 24.11 (Vicuna)"
	SUPPORT_END="2025-06-30"
	SUPPORT_URL="https://nixos.org/community.html"
	VARIANT=""
	VARIANT_ID=""
	VENDOR_NAME="NixOS"
	VENDOR_URL="https://nixos.org/"
	VERSION="24.11 (Vicuna)"
	VERSION_CODENAME=vicuna
	VERSION_ID="24.11"`

	tests := []struct {
		name             string
		path             string
		osrelease        string
		wantInventory    []*extractor.Inventory
		wantError        error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "valid",
			path:      "nix/store/xakcaxsqdzjszym0vji2r8n0wdy2inqc-perl5.38.2-FCGI-ProcManager-0.28/foo",
			osrelease: NixVicuna,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "perl5.38.2-FCGI-ProcManager",
					Version: "0.28",
					Metadata: &nix.Metadata{
						PackageName:       "perl5.38.2-FCGI-ProcManager",
						PackageVersion:    "0.28",
						PackageHash:       "xakcaxsqdzjszym0vji2r8n0wdy2inqc",
						PackageOutput:     "",
						OSID:              "nixos",
						OSVersionCodename: "vicuna",
						OSVersionID:       "24.11",
					},
					Locations: []string{"nix/store/xakcaxsqdzjszym0vji2r8n0wdy2inqc-perl5.38.2-FCGI-ProcManager-0.28/foo"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "valid",
			path:      "nix/store/q5dhwzcn82by5ndc7g0q83wsnn13qkqw-webdav-server-rs-unstable-2021-08-16/foo",
			osrelease: NixVicuna,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "webdav-server-rs",
					Version: "unstable-2021-08-16",
					Metadata: &nix.Metadata{
						PackageName:       "webdav-server-rs",
						PackageVersion:    "unstable-2021-08-16",
						PackageHash:       "q5dhwzcn82by5ndc7g0q83wsnn13qkqw",
						PackageOutput:     "",
						OSID:              "nixos",
						OSVersionCodename: "vicuna",
						OSVersionID:       "24.11",
					},
					Locations: []string{"nix/store/q5dhwzcn82by5ndc7g0q83wsnn13qkqw-webdav-server-rs-unstable-2021-08-16/foo"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:          "invalid package hash",
			path:          "nix/store/foo-webdav-server-rs-unstable-2021-08-16/foo",
			osrelease:     NixVicuna,
			wantInventory: nil,
		},
		{
			name:          "no package name",
			path:          "nix/store/xakcaxsqdzjszym0vji2r8n0wdy2inqc-0.28/foo",
			osrelease:     NixVicuna,
			wantInventory: nil,
		},
		{
			name:          "no package version",
			path:          "nix/store/xakcaxsqdzjszym0vji2r8n0wdy2inqc-perl5.38.2-FCGI-ProcManager/foo",
			osrelease:     NixVicuna,
			wantInventory: nil,
		},
		{
			name:          "invalid",
			path:          "nix/store/xzlmnp0lblcbscy36nlgif3js4mc68gm-base-system/etc/group",
			osrelease:     NixVicuna,
			wantInventory: nil,
		},
		{
			name:          "invalid",
			path:          "nix/store/a-b-c-d-e/foo",
			osrelease:     NixVicuna,
			wantInventory: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = nix.New()

			d := t.TempDir()
			createOsRelease(t, d, tt.osrelease)

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS(d),
				Path:   tt.path,
				Reader: nil,
				Root:   d,
				Info:   nil,
			}

			got, err := e.Extract(t.Context(), input)

			if err != nil {
				t.Errorf("err = %v", err)
			}

			if diff := cmp.Diff(tt.wantInventory, got); diff != "" {
				t.Errorf("Inventory mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	pkgName := "pkgName"
	pkgVersion := "pkgVersion"
	pkgHash := "pkgHash"
	pkgOutput := "pkgOutput"

	e := nix.Extractor{}
	tests := []struct {
		name     string
		metadata *nix.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "all fields present",
			metadata: &nix.Metadata{
				PackageName:       pkgName,
				PackageVersion:    pkgVersion,
				PackageHash:       pkgHash,
				PackageOutput:     pkgOutput,
				OSID:              "nixos",
				OSVersionCodename: "vicuna",
				OSVersionID:       "24.11",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNix,
				Name:    pkgName,
				Version: pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"distro": "vicuna",
				}),
			},
		},
		{
			name: "only VERSION_ID set",
			metadata: &nix.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				PackageHash:    pkgHash,
				PackageOutput:  pkgOutput,
				OSID:           "nixos",
				OSVersionID:    "24.11",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNix,
				Name:    pkgName,
				Version: pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"distro": "24.11",
				}),
			},
		},
		{
			name: "OS ID not set, fallback to Nixos",
			metadata: &nix.Metadata{
				PackageName:       pkgName,
				PackageVersion:    pkgVersion,
				PackageHash:       pkgHash,
				PackageOutput:     pkgOutput,
				OSVersionCodename: "vicuna",
				OSVersionID:       "24.11",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNix,
				Name:    pkgName,
				Version: pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"distro": "vicuna",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      pkgName,
				Version:   pkgVersion,
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

func createOsRelease(t *testing.T, root string, content string) {
	t.Helper()
	os.MkdirAll(filepath.Join(root, "etc"), 0755)
	err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "etc/os-release"), err)
	}
}
