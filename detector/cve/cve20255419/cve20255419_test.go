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
		name      string
		pkgs      []*extractor.Package
		wantVuln  int
		wantFixed string // optional: verify the fixedVersion on the first finding
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
			// C1: standalone Chrome 131 must report fixedVersion=137.0.7151.68,
			// NOT the Electron backport floor 132.0.6834.210. The backport floor
			// only applies to Electron-embedded Chromium, not standalone Chrome.
			name: "StandaloneChrome131FixedVersionIsUpstream",
			pkgs: []*extractor.Package{
				{Name: "google-chrome", Version: "131.0.6778.264", Locations: []string{"/chrome"}},
			},
			wantVuln:  1,
			wantFixed: "137.0.7151.68",
		},
		{
			// C2: "chromium-apps" is not a package name produced by any extractor;
			// the case was dead code and has been removed. Such a package is skipped.
			name: "ChromiumAppsPackageNameNotRecognized",
			pkgs: []*extractor.Package{
				{
					Name:      "chromium-apps",
					Version:   "137.0.7151.67",
					Locations: []string{"/chromiumapps"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "131.0.6778.264",
						VersionSource:   "chromium_binary",
					},
				},
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
			name: "ElectronBackportVersionWithoutChromiumCoreEvaluated",
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
			name: "ElectronOlderMajorWithoutChromiumCoreReported",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "24.1.3.8",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ElectronVersion: "24.1.3.8",
						VersionSource:   "plist_cf_bundle_version",
					},
				},
			},
			wantVuln: 1,
		},
		{
			name: "ElectronBelowBackportFixWithoutChromiumCoreReported",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "36.3.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ElectronVersion: "36.3.0",
						VersionSource:   "plist_cf_bundle_version",
					},
				},
			},
			wantVuln: 1,
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
			name: "ElectronUnknownMajorWithCoreBelowBackportFloorReported",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "39.4.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ChromiumVersion: "131.0.6778.264",
						ElectronVersion: "39.4.0",
						VersionSource:   "chromium_binary",
					},
				},
			},
			wantVuln: 1,
		},
		{
			name: "ElectronFourPartVersionComparedAsNumeric",
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
			wantVuln: 0,
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
		{
			// C3: stable "37.0.0" is newer than the fix "37.0.0-beta.3" in semver
			// (stable > any pre-release of the same version). Previously, the
			// numeric fast-path in isElectronVulnerable returned an error for this
			// input because "37.0.0-beta.3" is not a pure-numeric version string,
			// causing the package to be silently skipped instead of correctly
			// evaluated as not-vulnerable.
			name: "ElectronStable37NotVulnerable",
			pkgs: []*extractor.Package{
				{
					Name:      "electron",
					Version:   "37.0.0",
					Locations: []string{"/electron"},
					Metadata: &chromiumapps.Metadata{
						ElectronVersion: "37.0.0",
						VersionSource:   "plist_cf_bundle_version",
					},
				},
			},
			wantVuln: 0,
		},
		{
			// C5: Edge 135 (major <= 136) must be reported as vulnerable.
			// The previously redundant "v[0] < 136" and "v[0] == 136" switch
			// cases are now merged into a single "v[0] <= 136" case.
			name: "EdgeMajor135Reported",
			pkgs: []*extractor.Package{
				{Name: "microsoft-edge", Version: "135.0.3100.50", Locations: []string{"/edge"}},
			},
			wantVuln:  1,
			wantFixed: "136.0.3240.115",
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
			if tt.wantFixed != "" && len(finding.PackageVulns) > 0 {
				gotFixed := finding.PackageVulns[0].Vulnerability.Affected[0].Ranges[0].Events[1].Fixed
				if gotFixed != tt.wantFixed {
					t.Errorf("fixedVersion=%q want %q", gotFixed, tt.wantFixed)
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
