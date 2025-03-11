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

package module_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     module.Config
		wantCfg module.Config
	}{
		{
			name: "default",
			cfg:  module.DefaultConfig(),
			wantCfg: module.Config{
				MaxFileSizeBytes: 100 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: module.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: module.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := module.New(tt.cfg)
			if diff := cmp.Diff(tt.wantCfg, got.Config()); diff != "" {
				t.Errorf("New(%+v).Config(): (-want +got):\n%s", tt.cfg, diff)
			}
		})
	}
}

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
			name:             "required *.ko file",
			path:             "/usr/lib/modules/6.8.0-48-generic/kernel/arch/x86/crypto/cast5-avx-x86_64.ko",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file required if file size < max file size",
			path:             "/usr/lib/modules/6.8.0-48-generic/kernel/arch/x86/crypto/cast5-avx-x86_64.ko",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file required if file size == max file size",
			path:             "/usr/lib/modules/6.8.0-48-generic/kernel/arch/x86/crypto/cast5-avx-x86_64.ko",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file not required if file size > max file size",
			path:             "/usr/lib/modules/6.8.0-48-generic/kernel/arch/x86/crypto/cast5-avx-x86_64.ko",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "file required if max file size set to 0",
			path:             "/usr/lib/modules/6.8.0-48-generic/kernel/arch/x86/crypto/cast5-avx-x86_64.ko",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "not required",
			path:         "/usr/lib/modules/6.8.0-48-generic/kernel/arch/x86/crypto/cast5-avx-x86_64.o",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = module.New(module.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

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

const UbuntuJammy = `PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
`

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		cfg              module.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "valid *.ko file",
			path:      "testdata/valid",
			osrelease: UbuntuJammy,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "intel_oaktrail",
					Version: "0.4ac1",
					Metadata: &module.Metadata{
						PackageName:                    "intel_oaktrail",
						PackageVersion:                 "0.4ac1",
						PackageVermagic:                "6.5.0-45-generic SMP preempt mod_unload modversions",
						PackageSourceVersionIdentifier: "69B4F4432F52708A284377E",
						OSID:                           "ubuntu",
						OSVersionCodename:              "jammy",
						OSVersionID:                    "22.04",
						PackageAuthor:                  "Yin Kangkai (kangkai.yin@intel.com)",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "valid *.ko file without version, deps, author",
			path:      "testdata/valid_no_vers_deps_auth",
			osrelease: UbuntuJammy,
			wantInventory: []*extractor.Inventory{
				{
					Name: "intel_mrfld_pwrbtn",
					Metadata: &module.Metadata{
						PackageName:                    "intel_mrfld_pwrbtn",
						PackageVermagic:                "6.8.0-49-generic SMP preempt mod_unload modversions",
						PackageSourceVersionIdentifier: "F64DA2CCFC87C17684B7B8B",
						OSID:                           "ubuntu",
						OSVersionCodename:              "jammy",
						OSVersionID:                    "22.04",
					},
					Locations: []string{"testdata/valid_no_vers_deps_auth"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid *.ko file, no .modinfo section",
			path:             "testdata/invalid",
			osrelease:        UbuntuJammy,
			wantInventory:    nil,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:      "no os version",
			path:      "testdata/valid",
			osrelease: `ID=ubuntu`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "intel_oaktrail",
					Version: "0.4ac1",
					Metadata: &module.Metadata{
						PackageName:                    "intel_oaktrail",
						PackageVersion:                 "0.4ac1",
						PackageVermagic:                "6.5.0-45-generic SMP preempt mod_unload modversions",
						PackageSourceVersionIdentifier: "69B4F4432F52708A284377E",
						OSID:                           "ubuntu",
						PackageAuthor:                  "Yin Kangkai (kangkai.yin@intel.com)",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "missing osrelease",
			path: "testdata/valid",
			wantInventory: []*extractor.Inventory{
				{
					Name:    "intel_oaktrail",
					Version: "0.4ac1",
					Metadata: &module.Metadata{
						PackageName:                    "intel_oaktrail",
						PackageVersion:                 "0.4ac1",
						PackageVermagic:                "6.5.0-45-generic SMP preempt mod_unload modversions",
						PackageSourceVersionIdentifier: "69B4F4432F52708A284377E",
						PackageAuthor:                  "Yin Kangkai (kangkai.yin@intel.com)",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = module.New(module.Config{
				Stats:            collector,
				MaxFileSizeBytes: 100,
			})

			d := t.TempDir()
			createOsRelease(t, d, tt.osrelease)

			// Opening and Reading the Test File
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
				FS: scalibrfs.DirFS(d), Path: tt.path, Reader: r, Root: d, Info: info,
			}

			got, err := e.Extract(t.Context(), input)

			if diff := cmp.Diff(tt.wantInventory, got); diff != "" {
				t.Errorf("Inventory mismatch (-want +got):\n%s", diff)
			}

			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	pkgName := "pkgName"
	pkgVersion := "pkgVersion"
	pkgVermagic := "pkgVermagic"
	pkgSourceVersionIdentifier := "pkgSourceVersionIdentifier"
	pkgAuthor := "pkgAuthor"

	e := module.Extractor{}
	tests := []struct {
		name     string
		metadata *module.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "all fields present",
			metadata: &module.Metadata{
				PackageName:                    pkgName,
				PackageVersion:                 pkgVersion,
				PackageVermagic:                pkgVermagic,
				PackageSourceVersionIdentifier: pkgSourceVersionIdentifier,
				PackageAuthor:                  pkgAuthor,
				OSID:                           "ubuntu",
				OSVersionCodename:              "jammy",
				OSVersionID:                    "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      pkgName,
				Namespace: "ubuntu",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			name: "only VERSION_ID set",
			metadata: &module.Metadata{
				PackageName:                    pkgName,
				PackageVersion:                 pkgVersion,
				PackageVermagic:                pkgVermagic,
				PackageSourceVersionIdentifier: pkgSourceVersionIdentifier,
				PackageAuthor:                  pkgAuthor,
				OSID:                           "ubuntu",
				OSVersionID:                    "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      pkgName,
				Namespace: "ubuntu",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			name: "OS ID not set, fallback to linux",
			metadata: &module.Metadata{
				PackageName:                    pkgName,
				PackageVersion:                 pkgVersion,
				PackageVermagic:                pkgVermagic,
				PackageSourceVersionIdentifier: pkgSourceVersionIdentifier,
				PackageAuthor:                  pkgAuthor,
				OSVersionID:                    "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      pkgName,
				Namespace: "linux",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
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

func TestEcosystem(t *testing.T) {
	e := module.Extractor{}
	tests := []struct {
		name     string
		metadata *module.Metadata
		want     string
	}{
		{
			name: "OS ID present",
			metadata: &module.Metadata{
				OSID: "ubuntu",
			},
			want: "Ubuntu",
		},
		{
			name:     "OS ID not present",
			metadata: &module.Metadata{},
			want:     "Linux",
		},
		{
			name: "OS version present",
			metadata: &module.Metadata{
				OSID:        "ubuntu",
				OSVersionID: "22.04",
			},
			want: "Ubuntu:22.04",
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
