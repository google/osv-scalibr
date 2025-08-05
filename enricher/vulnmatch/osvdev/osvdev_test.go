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

package osvdev_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

func TestEnrich(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	// TODO: add a mock client
	e := osvdev.New()

	var (
		jsPkg      = &extractor.Package{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM}
		pyPkg      = &extractor.Package{Name: "requests", Version: "2.26.0", PURLType: purl.TypePyPi}
		goPkg      = &extractor.Package{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang}
		fzfPkg     = &extractor.Package{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew}
		unknownPkg = &extractor.Package{Name: "unknown", PURLType: purl.TypeGolang}
	)

	tests := []struct {
		name     string
		packages []*extractor.Package
		//nolint:containedctx
		ctx              context.Context
		wantErr          error
		wantPackageVulns []*inventory.PackageVuln
	}{
		{
			name:     "ctx_cancelled",
			ctx:      cancelledContext,
			wantErr:  cmpopts.AnyError,
			packages: []*extractor.Package{jsPkg, pyPkg, goPkg},
		},
		{
			name: "initial_query_timeout",
			// TODO: test
		},
		{
			name:     "simple_test",
			packages: []*extractor.Package{goPkg},
			wantPackageVulns: []*inventory.PackageVuln{
				{
					Vulnerability: osvschema.Vulnerability{
						SchemaVersion: "1.7.0",
						ID:            "GHSA-2c4m-59x9-fr2g",
						Modified:      time.Date(2023, 11, 8, 4, 12, 18, 674169000, time.UTC),
						Published:     time.Date(2023, 5, 12, 20, 19, 25, 0, time.UTC),
						Aliases:       []string{"CVE-2023-29401", "GO-2023-1737"},
						Summary:       "Gin Web Framework does not properly sanitize filename parameter ...",
						Details:       "The filename parameter of the Context.FileAttachment function is ...",
						Severity:      []osvschema.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}},
						References: []osvschema.Reference{
							{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-29401"},
							{Type: "WEB", URL: "https://github.com/gin-gonic/gin/issues/3555"},
							{Type: "WEB", URL: "https://github.com/gin-gonic/gin/pull/3556"},
							{Type: "PACKAGE", URL: "https://github.com/gin-gonic/gin"},
							{Type: "WEB", URL: "https://github.com/gin-gonic/gin/releases/tag/v1.9.1"},
							{Type: "WEB", URL: "https://pkg.go.dev/vuln/GO-2023-1737"},
						},
						DatabaseSpecific: map[string]any{
							"cwe_ids":            []any{"CWE-494"},
							"github_reviewed":    true,
							"github_reviewed_at": "2023-05-12T20:19:25Z",
							"nvd_published_at":   "2023-06-08T21:15:16Z",
							"severity":           "MODERATE",
						},
						Affected: []osvschema.Affected{
							{
								Package: osvschema.Package{
									Ecosystem: goPkg.Ecosystem(),
									Name:      goPkg.Name,
									Purl:      "pkg:golang/github.com/gin-gonic/gin",
								},
								Ranges: []osvschema.Range{
									{
										Type:   "SEMVER",
										Events: []osvschema.Event{{Introduced: "1.3.1-0.20190301021747-ccb9e902956d"}, {Fixed: "1.9.1"}}},
								},
								DatabaseSpecific: map[string]any{
									"source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2023/05/GHSA-2c4m-59x9-fr2g/GHSA-2c4m-59x9-fr2g.json",
								},
							},
						},
					},
					Packages: []*extractor.Package{goPkg},
					Plugins:  []string{osvdev.Name},
				},
				{
					Vulnerability: osvschema.Vulnerability{
						SchemaVersion: "1.7.0",
						ID:            "GHSA-3vp4-m3rf-835h",
						Aliases:       []string{"CVE-2023-26125"},
						Summary:       "Improper input validation in github.com/gin-gonic/gin",
						Details:       "Versions of the package github.com/gin-gonic/gin before version ...",
						Severity:      []osvschema.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"}},
						Modified:      time.Date(2023, 11, 8, 4, 11, 58, 943766000, time.UTC),
						Published:     time.Date(2023, 5, 4, 6, 30, 12, 0, time.UTC),
						Affected: []osvschema.Affected{
							{
								Package: osvschema.Package{
									Ecosystem: goPkg.Ecosystem(),
									Name:      goPkg.Name,
									Purl:      "pkg:golang/github.com/gin-gonic/gin",
								},
								Ranges: []osvschema.Range{
									{
										Type:   "SEMVER",
										Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "1.9.0"}},
									},
								},
								DatabaseSpecific: map[string]any{
									"source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2023/05/GHSA-3vp4-m3rf-835h/GHSA-3vp4-m3rf-835h.json",
								},
							},
						},
						References: []osvschema.Reference{
							{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-26125"},
							{Type: "WEB", URL: "https://github.com/gin-gonic/gin/pull/3500"},
							{Type: "WEB", URL: "https://github.com/gin-gonic/gin/pull/3503"},
							{Type: "WEB", URL: "https://github.com/t0rchwo0d/gin/commit/fd9f98e70fb4107ee68c783482d231d35e60507b"},
							{Type: "PACKAGE", URL: "https://github.com/gin-gonic/gin"},
							{Type: "WEB", URL: "https://github.com/gin-gonic/gin/releases/tag/v1.9.0"},
							{Type: "WEB", URL: "https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMGINGONICGIN-3324285"},
						},
						DatabaseSpecific: map[string]any{
							"cwe_ids":            []any{"CWE-20", "CWE-77"},
							"github_reviewed":    true,
							"github_reviewed_at": "2023-05-05T02:20:00Z",
							"nvd_published_at":   "2023-05-04T05:15:09Z",
							"severity":           "MODERATE",
						},
					},
					Packages: []*extractor.Package{goPkg},
					Plugins:  []string{osvdev.Name},
				},
				{
					Vulnerability: osvschema.Vulnerability{
						SchemaVersion: "1.7.0",
						ID:            "GO-2023-1737",
						Aliases:       []string{"CVE-2023-29401", "GHSA-2c4m-59x9-fr2g"},
						Summary:       "Improper handling of filenames in Content-Disposition HTTP heade...",
						Details:       "The filename parameter of the Context.FileAttachment function is ...",
						DatabaseSpecific: map[string]any{
							"review_status": string("REVIEWED"),
							"url":           string("https://pkg.go.dev/vuln/GO-2023-1737"),
						},
						Affected: []osvschema.Affected{
							{
								Package: osvschema.Package{
									Ecosystem: goPkg.Ecosystem(),
									Name:      goPkg.Name,
									Purl:      "pkg:golang/github.com/gin-gonic/gin",
								},
								Ranges: []osvschema.Range{
									{
										Type:   "SEMVER",
										Events: []osvschema.Event{{Introduced: "1.3.1-0.20190301021747-ccb9e902956d"}, {Fixed: "1.9.1"}},
									},
								},
								DatabaseSpecific: map[string]any{"source": string("https://vuln.go.dev/ID/GO-2023-1737.json")},
								EcosystemSpecific: map[string]any{
									"imports": []any{
										map[string]any{"path": string("github.com/gin-gonic/gin"), "symbols": []any{"Context.FileAttachment"}},
									},
								},
							},
						},
						Modified:  time.Date(2024, 5, 20, 16, 3, 47, 0, time.UTC),
						Published: time.Date(2023, 5, 11, 18, 59, 56, 0, time.UTC),
						Credits:   []osvschema.Credit{{Name: "motoyasu-saburi"}},
						References: []osvschema.Reference{
							{Type: "REPORT", URL: "https://github.com/gin-gonic/gin/issues/3555"},
							{Type: "FIX", URL: "https://github.com/gin-gonic/gin/pull/3556"},
							{Type: "WEB", URL: "https://github.com/gin-gonic/gin/releases/tag/v1.9.1"},
						},
					},
					Packages: []*extractor.Package{goPkg},
					Plugins:  []string{osvdev.Name},
				},
			},
		},
		{
			name:     "not_covered_purl_type",
			packages: []*extractor.Package{fzfPkg},
		},
		{
			name:     "unknown_package",
			packages: []*extractor.Package{unknownPkg},
		},
		{
			name: "interleaving_covered_not_coverdd",
			// TODO: implement
		},
		{
			name: "not_empty_local_inventory_vulns",
			// TODO: implement
		},
		{
			name: "one_local_one_remote__same_pkg_same_cve",
			// TODO: implement
		},
		{
			name: "one_local_one_remote__different_pkg_same_cve",
			// TODO: implement
		},
		{
			name: "exploitability_signals",
			// TODO: implement
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = context.Background()
			}

			var input *enricher.ScanInput

			packages := copier.Copy(tt.packages).([]*extractor.Package)
			inv := &inventory.Inventory{Packages: packages}

			err := e.Enrich(tt.ctx, input, inv)
			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Enrich(%v) error: %v, want %v", tt.packages, err, tt.wantErr)
			}

			want := &inventory.Inventory{
				PackageVulns: tt.wantPackageVulns,
				Packages:     tt.packages,
			}

			sortPkgVulns := cmpopts.SortSlices(func(a, b *inventory.PackageVuln) bool {
				return a.Vulnerability.ID < b.Vulnerability.ID
			})

			diff := cmp.Diff(
				want, inv,
				sortPkgVulns,
				// TODO: add this back
				cmpopts.IgnoreFields(osvschema.Vulnerability{}, "Details", "Summary"),
			)

			if diff != "" {
				t.Errorf("Enrich(%v): unexpected diff (-want +got): %v", tt.packages, diff)
			}
		})
	}
}
