// Copyright 2026 Google LLC
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

package linuxdistro

import (
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
)

type fakeFS map[string]string

func (f fakeFS) Open(name string) (fs.File, error) {
	return os.Open(f[name])
}
func (fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, errors.New("not implemented")
}
func (fakeFS) Stat(name string) (fs.FileInfo, error) {
	return nil, errors.New("not implemented")
}

func TestEOLLinuxDistro(t *testing.T) {
	wantDescription := "The system is running a Linux distribution that has reached " +
		"end-of-life (EOL) and is no longer maintained by the vendor. This means it no " +
		"longer receives security updates or patches."
	wantRecommendation := "Upgrade the operating system to a supported release or arrange " +
		"an extended support with the vendor."
	tests := []struct {
		name        string
		now         string
		fsys        scalibrfs.FS
		wantFinding []*inventory.GenericFinding
	}{
		{
			name: "fedora-42-not-eol",
			now:  "2020-01-01",
			fsys: fakeFS{
				"etc/os-release": "testdata/fedora_42_os_release",
			},
		},
		{
			name: "fedora-42-eol",
			now:  "2030-01-01",
			fsys: fakeFS{
				"etc/os-release": "testdata/fedora_42_os_release",
			},
			wantFinding: []*inventory.GenericFinding{{
				Adv: &inventory.GenericFindingAdvisory{
					ID: &inventory.AdvisoryID{
						Publisher: "SCALIBR",
						Reference: "linux-end-of-life",
					},
					Title:          "End-of-Life operating system",
					Description:    wantDescription,
					Recommendation: wantRecommendation,
					Sev:            inventory.SeverityCritical,
				},
				Target: &inventory.GenericFindingTargetDetails{Extra: "distro: fedora"},
			}},
		},
		{
			name: "ubuntu-22-04-not-eol",
			now:  "2026-01-01",
			fsys: fakeFS{
				"etc/os-release": "testdata/ubuntu_22.04_os_release",
			},
		},
		{
			name: "ubuntu-22-04-eol",
			now:  "2030-01-01",
			fsys: fakeFS{
				"etc/os-release": "testdata/ubuntu_22.04_os_release",
			},
			wantFinding: []*inventory.GenericFinding{{
				Adv: &inventory.GenericFindingAdvisory{
					ID: &inventory.AdvisoryID{
						Publisher: "SCALIBR",
						Reference: "linux-end-of-life",
					},
					Title:          "End-of-Life operating system",
					Description:    wantDescription,
					Recommendation: wantRecommendation,
					Sev:            inventory.SeverityCritical,
				},
				Target: &inventory.GenericFindingTargetDetails{Extra: "distro: ubuntu"},
			}},
		},
		{
			name: "ubuntu-22-04-pro-not-eol",
			now:  "2030-01-01",
			fsys: fakeFS{
				"etc/os-release": "testdata/ubuntu_22.04_os_release",
				"/etc/apt/sources.list.d/ubuntu-esm-infra.sources": "testdata/ubuntu-esm-infra.sources",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now = func() time.Time {
				n, err := time.Parse("2006-01-02", tc.now)
				if err != nil {
					t.Fatalf("detector.Scan(%v) invalid date: %v", tc.now, err)
				}
				return n
			}
			d := Detector{}
			finding, err := d.Scan(t.Context(), &scalibrfs.ScanRoot{FS: tc.fsys}, nil)
			if err != nil {
				t.Errorf("detector.Scan(%v) unexpected error: %v", tc.fsys, err)
			}
			if diff := cmp.Diff(tc.wantFinding, finding.GenericFindings); diff != "" {
				t.Errorf("detector.Scan(%v): unexpected findings (-want +got):\n%s", tc.fsys, diff)
			}
		})
	}
}
