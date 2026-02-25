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

package cve20255419_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/osv-scalibr/detector/cve/cve20255419"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/chromiumapps"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/packageindex"
)

func TestScan(t *testing.T) {
	tests := []struct {
		name     string
		pkgs     []*extractor.Package
		wantVuln int
	}{
		{
			name: "VulnerableChromeAndEdge",
			pkgs: []*extractor.Package{
				{Name: "google-chrome", Version: "137.0.7151.67", Locations: []string{"/chrome"}},
				{Name: "microsoft-edge", Version: "137.0.3296.61", Locations: []string{"/edge"}},
				{Name: "chromium", Version: "137.0.7151.67", Locations: []string{"/chromium"}},
			},
			wantVuln: 3,
		},
		{
			name: "FixedVersionsNotReported",
			pkgs: []*extractor.Package{
				{Name: "google-chrome", Version: "137.0.7151.68", Locations: []string{"/chrome"}},
				{Name: "microsoft-edge", Version: "137.0.3296.62", Locations: []string{"/edge"}},
				{Name: "chromium", Version: "137.0.7151.68", Locations: []string{"/chromium"}},
			},
			wantVuln: 0,
		},
		{
			name: "EdgeExtendedStableFixedVersionNotReported",
			pkgs: []*extractor.Package{
				{Name: "microsoft-edge", Version: "136.0.3240.115", Locations: []string{"/edge"}},
			},
			wantVuln: 0,
		},
		{
			name: "EdgeExtendedStableBelowFixedReported",
			pkgs: []*extractor.Package{
				{Name: "microsoft-edge", Version: "136.0.3240.104", Locations: []string{"/edge"}},
			},
			wantVuln: 1,
		},
		{
			name: "EdgeNewerMajorNotReported",
			pkgs: []*extractor.Package{
				{Name: "microsoft-edge", Version: "145.0.3800.70", Locations: []string{"/edge"}},
			},
			wantVuln: 0,
		},
		{
			name: "InvalidVersionSkipped",
			pkgs: []*extractor.Package{
				{Name: "google-chrome", Version: "137.0.7151", Locations: []string{"/chrome"}},
			},
			wantVuln: 0,
		},
		{
			name: "UnknownPackageSkipped",
			pkgs: []*extractor.Package{
				{Name: "unknown-browser", Version: "1.2.3.4", Locations: []string{"/unknown"}},
			},
			wantVuln: 0,
		},
		{
			name: "ElectronWithoutChromiumCoreSkipped",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "39.4.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ElectronVersion: "39.4.0",
						VersionSource:   "plist_cf_bundle_version",
					},
				},
			},
			wantVuln: 0,
		},
		{
			name: "ElectronBackportVersionWithoutChromiumCoreSkipped",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "36.4.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ElectronVersion: "36.4.0",
						VersionSource:   "plist_cf_bundle_version",
					},
				},
			},
			wantVuln: 0,
		},
		{
			name: "ElectronWithBackportFixedNotReported",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "39.4.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "136.0.7103.149",
						ElectronVersion: "36.4.0",
						VersionSource:   "chromium_binary",
					},
				},
			},
			wantVuln: 0,
		},
		{
			name: "ElectronWithBackportBelowFixedReported",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "36.3.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "136.0.7103.120",
						ElectronVersion: "36.3.0",
						VersionSource:   "chromium_binary",
					},
				},
			},
			wantVuln: 1,
		},
		{
			name: "ElectronWithBackportPreReleaseFixedNotReported",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "37.0.0-beta.3",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "138.0.7190.0",
						ElectronVersion: "37.0.0-beta.3",
						VersionSource:   "chromium_binary",
					},
				},
			},
			wantVuln: 0,
		},
		{
			name: "ElectronWithBackportPreReleaseBelowFixedReported",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "37.0.0-beta.2",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "138.0.7189.0",
						ElectronVersion: "37.0.0-beta.2",
						VersionSource:   "chromium_binary",
					},
				},
			},
			wantVuln: 1,
		},
		{
			name: "ElectronUnknownMajorFallsBackToChromiumCore",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "39.4.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "136.0.7100.1",
						ElectronVersion: "39.4.0",
						VersionSource:   "chromium_binary",
					},
				},
			},
			wantVuln: 1,
		},
		{
			name: "ElectronMalformedVersionFallsBackToChromiumCore",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "36.4.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "136.0.7103.120",
						ElectronVersion: "36.4.0.1",
						VersionSource:   "chromium_binary",
					},
				},
			},
			wantVuln: 1,
		},
		{
			name: "ElectronWithFixedChromiumCoreNotReported",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "39.4.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "142.0.7444.265",
						ElectronVersion: "39.4.0",
						VersionSource:   "chromium_binary",
					},
				},
			},
			wantVuln: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			px, err := packageindex.New(tt.pkgs)
			if err != nil {
				t.Fatalf("packageindex.New() err: %v", err)
			}

			det, err := cve20255419.New(nil)
			if err != nil {
				t.Fatalf("New() err: %v", err)
			}
			finding, err := det.Scan(t.Context(), &scalibrfs.ScanRoot{}, px)
			if err != nil {
				t.Fatalf("Scan() err: %v", err)
			}
			if got := len(finding.PackageVulns); got != tt.wantVuln {
				t.Fatalf("Scan() findings=%d want %d", got, tt.wantVuln)
			}
			for _, v := range finding.PackageVulns {
				if v.Vulnerability == nil || v.Vulnerability.Id != "CVE-2025-5419" {
					t.Fatalf("unexpected vulnerability %#v", v.Vulnerability)
				}
				if v.Package == nil {
					t.Fatalf("expected vulnerable package attached")
				}
			}
		})
	}
}

func TestScanCancelled(t *testing.T) {
	px, err := packageindex.New([]*extractor.Package{
		{Name: "google-chrome", Version: "137.0.7151.67", Locations: []string{"/chrome"}},
	})
	if err != nil {
		t.Fatalf("packageindex.New() err: %v", err)
	}

	det, err := cve20255419.New(nil)
	if err != nil {
		t.Fatalf("New() err: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = det.Scan(ctx, &scalibrfs.ScanRoot{}, px)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() err=%v want %v", err, context.Canceled)
	}
}
