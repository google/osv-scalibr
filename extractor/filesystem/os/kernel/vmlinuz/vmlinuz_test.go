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

package vmlinuz_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz"
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
		cfg     vmlinuz.Config
		wantCfg vmlinuz.Config
	}{
		{
			name: "default",
			cfg:  vmlinuz.DefaultConfig(),
			wantCfg: vmlinuz.Config{
				MaxFileSizeBytes: 30 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: vmlinuz.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: vmlinuz.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vmlinuz.New(tt.cfg)
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
			name:             "required vmlinuz file",
			path:             "boot/foo/vmlinuz",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "required vmlinuz-* file",
			path:             "boot/foo/voo/zoo/vmlinuz-x.y.z",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file required if file size < max file size",
			path:             "boot/foo/voo/zoo/vmlinuz",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file required if file size == max file size",
			path:             "boot/foo/voo/zoo/vmlinuz",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file not required if file size > max file size",
			path:             "boot/foo/voo/zoo/vmlinuz",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "file required if max file size set to 0",
			path:             "boot/foo/voo/zoo/vmlinuz",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "not required",
			path:         "usr/lib/foo/vmlinuzfoo",
			wantRequired: false,
		},
		{
			name:         "not required",
			path:         "boot/foo/voo/zoo/foovmlinuz-",
			wantRequired: false,
		},
		{
			name:         "not required",
			path:         "boot/foo/voo/zoo/vmlinuz.old",
			wantRequired: false,
		},
		{
			name:         "not required",
			path:         "usr/foo/voo/zoo/vmlinuz.old",
			wantRequired: false,
		},
		{
			name:         "not required",
			path:         "var/foo/voo/zoo/vmlinuz-x.y.z",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = vmlinuz.New(vmlinuz.Config{
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
		cfg              vmlinuz.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "valid vmlinuz file",
			path:      "testdata/valid",
			osrelease: UbuntuJammy,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "Linux Kernel",
					Version: "6.8.0-49-generic",
					Metadata: &vmlinuz.Metadata{
						Name:              "Linux Kernel",
						Version:           "6.8.0-49-generic",
						Architecture:      "x86",
						ExtendedVersion:   "6.8.0-49-generic (buildd@lcy02-amd64-103) #49~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Wed Nov  6 17:42:15 UTC 2",
						Format:            "bzImage",
						SwapDevice:        14,
						VideoMode:         "Video mode 65535",
						OSID:              "ubuntu",
						OSVersionCodename: "jammy",
						OSVersionID:       "22.04",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:          "invalid vmlinuz file",
			path:          "testdata/invalid",
			osrelease:     UbuntuJammy,
			wantInventory: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = vmlinuz.New(vmlinuz.Config{
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
		})
	}
}

func TestToPURL(t *testing.T) {
	name := "Linux Kernel"
	version := "version"
	architecture := "architecture"
	extendedVersion := "extendedVersion"
	format := "format"
	swapDevice := int32(10)
	rootDevice := int32(11)
	videoMode := "videoMode"
	rwRootFS := true

	e := vmlinuz.Extractor{}
	tests := []struct {
		name     string
		metadata *vmlinuz.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "all fields present",
			metadata: &vmlinuz.Metadata{
				Name:              name,
				Version:           version,
				Architecture:      architecture,
				ExtendedVersion:   extendedVersion,
				Format:            format,
				SwapDevice:        swapDevice,
				RootDevice:        rootDevice,
				VideoMode:         videoMode,
				OSID:              "ubuntu",
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
				RWRootFS:          rwRootFS,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "ubuntu",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			name: "only VERSION_ID set",
			metadata: &vmlinuz.Metadata{
				Name:            name,
				Version:         version,
				Architecture:    architecture,
				ExtendedVersion: extendedVersion,
				Format:          format,
				SwapDevice:      swapDevice,
				RootDevice:      rootDevice,
				VideoMode:       videoMode,
				OSID:            "ubuntu",
				OSVersionID:     "22.04",
				RWRootFS:        rwRootFS,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "ubuntu",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			name: "OS ID not set, fallback to linux",
			metadata: &vmlinuz.Metadata{
				Name:            name,
				Version:         version,
				Architecture:    architecture,
				ExtendedVersion: extendedVersion,
				Format:          format,
				SwapDevice:      swapDevice,
				RootDevice:      rootDevice,
				VideoMode:       videoMode,
				OSVersionID:     "22.04",
				RWRootFS:        rwRootFS,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      name,
				Version:   version,
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
	e := vmlinuz.Extractor{}
	tests := []struct {
		name     string
		metadata *vmlinuz.Metadata
		want     string
	}{
		{
			name: "OS ID present",
			metadata: &vmlinuz.Metadata{
				OSID: "ubuntu",
			},
			want: "Ubuntu",
		},
		{
			name:     "OS ID not present",
			metadata: &vmlinuz.Metadata{},
			want:     "Linux",
		},
		{
			name: "OS version present",
			metadata: &vmlinuz.Metadata{
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
