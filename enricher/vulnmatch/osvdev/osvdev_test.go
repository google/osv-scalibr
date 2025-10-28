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
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev/fakeclient"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEnrich(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	var (
		jsPkg      = &extractor.Package{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM}
		goPkg      = &extractor.Package{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang}
		fzfPkg     = &extractor.Package{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew}
		pyPkg      = &extractor.Package{Name: "requests", Version: "1.63.0", PURLType: purl.TypePyPi}
		unknownPkg = &extractor.Package{Name: "unknown", PURLType: purl.TypeGolang}

		goPkgWithSignals = &extractor.Package{
			Name:     "github.com/gin-gonic/gin",
			Version:  "1.8.1",
			PURLType: purl.TypeGolang,
			ExploitabilitySignals: []*vex.PackageExploitabilitySignal{
				{
					Plugin: "annotator/example", VulnIdentifiers: []string{"GHSA-2c4m-59x9-fr2g"},
				},
			}}
	)

	var (
		goVuln1 = osvschema.Vulnerability{
			SchemaVersion: "1.7.0",
			Id:            "GHSA-2c4m-59x9-fr2g",
			Modified:      timestamppb.New(time.Date(2023, 11, 8, 4, 12, 18, 674169000, time.UTC)),
			Published:     timestamppb.New(time.Date(2023, 5, 12, 20, 19, 25, 0, time.UTC)),
			Aliases:       []string{"CVE-2023-29401", "GO-2023-1737"},
			Summary:       "Gin Web Framework does not properly sanitize filename parameter ...",
			Details:       "The filename parameter of the Context.FileAttachment function is ...",
			Severity:      []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}},
			References: []*osvschema.Reference{
				{Type: osvschema.Reference_ADVISORY, Url: "https://nvd.nist.gov/vuln/detail/CVE-2023-29401"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/gin-gonic/gin/issues/3555"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/gin-gonic/gin/pull/3556"},
				{Type: osvschema.Reference_PACKAGE, Url: "https://github.com/gin-gonic/gin"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/gin-gonic/gin/releases/tag/v1.9.1"},
				{Type: osvschema.Reference_WEB, Url: "https://pkg.go.dev/vuln/GO-2023-1737"},
			},
			DatabaseSpecific: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"cwe_ids": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
						{Kind: &structpb.Value_StringValue{StringValue: "CWE-494"}},
					}}}},
					"github_reviewed":    {Kind: &structpb.Value_BoolValue{BoolValue: true}},
					"github_reviewed_at": {Kind: &structpb.Value_StringValue{StringValue: "2023-05-12T20:19:25Z"}},
					"nvd_published_at":   {Kind: &structpb.Value_StringValue{StringValue: "2023-06-08T21:15:16Z"}},
					"severity":           {Kind: &structpb.Value_StringValue{StringValue: "MODERATE"}},
				},
			},
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: goPkg.Ecosystem().String(),
						Name:      goPkg.Name,
						Purl:      "pkg:golang/github.com/gin-gonic/gin",
					},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "1.3.1-0.20190301021747-ccb9e902956d"}, {Fixed: "1.9.1"}}},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2023/05/GHSA-2c4m-59x9-fr2g/GHSA-2c4m-59x9-fr2g.json"}},
						},
					},
				},
			},
		}

		goVuln2 = osvschema.Vulnerability{
			SchemaVersion: "1.7.0",
			Id:            "GHSA-3vp4-m3rf-835h",
			Aliases:       []string{"CVE-2023-26125"},
			Summary:       "Improper input validation in github.com/gin-gonic/gin",
			Details:       "Versions of the package github.com/gin-gonic/gin before version ...",
			Severity:      []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"}},
			Modified:      timestamppb.New(time.Date(2023, 11, 8, 4, 11, 58, 943766000, time.UTC)),
			Published:     timestamppb.New(time.Date(2023, 5, 4, 6, 30, 12, 0, time.UTC)),
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: goPkg.Ecosystem().String(),
						Name:      goPkg.Name,
						Purl:      "pkg:golang/github.com/gin-gonic/gin",
					},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.9.0"}}},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2023/05/GHSA-3vp4-m3rf-835h/GHSA-3vp4-m3rf-835h.json"}},
						},
					},
				},
			},
			References: []*osvschema.Reference{
				{Type: osvschema.Reference_ADVISORY, Url: "https://nvd.nist.gov/vuln/detail/CVE-2023-26125"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/gin-gonic/gin/pull/3500"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/gin-gonic/gin/pull/3503"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/t0rchwo0d/gin/commit/fd9f98e70fb4107ee68c783482d231d35e60507b"},
				{Type: osvschema.Reference_PACKAGE, Url: "https://github.com/gin-gonic/gin"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/gin-gonic/gin/releases/tag/v1.9.0"},
				{Type: osvschema.Reference_WEB, Url: "https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMGINGONICGIN-3324285"},
			},
			DatabaseSpecific: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"cwe_ids": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
						{Kind: &structpb.Value_StringValue{StringValue: "CWE-20"}},
						{Kind: &structpb.Value_StringValue{StringValue: "CWE-77"}},
					}}}},
					"github_reviewed":    {Kind: &structpb.Value_BoolValue{BoolValue: true}},
					"github_reviewed_at": {Kind: &structpb.Value_StringValue{StringValue: "2023-05-05T02:20:00Z"}},
					"nvd_published_at":   {Kind: &structpb.Value_StringValue{StringValue: "2023-05-04T05:15:09Z"}},
					"severity":           {Kind: &structpb.Value_StringValue{StringValue: "MODERATE"}},
				},
			},
		}

		goVuln3 = osvschema.Vulnerability{
			SchemaVersion: "1.7.0",
			Id:            "GO-2023-1737",
			Aliases:       []string{"CVE-2023-29401", "GHSA-2c4m-59x9-fr2g"},
			Summary:       "Improper handling of filenames in Content-Disposition HTTP heade...",
			Details:       "The filename parameter of the Context.FileAttachment function is ...",
			DatabaseSpecific: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"review_status": {Kind: &structpb.Value_StringValue{StringValue: "REVIEWED"}},
					"url":           {Kind: &structpb.Value_StringValue{StringValue: "https://pkg.go.dev/vuln/GO-2023-1737"}},
				},
			},
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: goPkg.Ecosystem().String(),
						Name:      goPkg.Name,
						Purl:      "pkg:golang/github.com/gin-gonic/gin",
					},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "1.3.1-0.20190301021747-ccb9e902956d"}, {Fixed: "1.9.1"}}},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://vuln.go.dev/ID/GO-2023-1737.json"}},
						},
					},
					EcosystemSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"imports": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{
								Values: []*structpb.Value{
									{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{
										Fields: map[string]*structpb.Value{
											"path": {Kind: &structpb.Value_StringValue{StringValue: "github.com/gin-gonic/gin"}},
											"symbols": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{
												Values: []*structpb.Value{
													{Kind: &structpb.Value_StringValue{StringValue: "Context.FileAttachment"}},
												},
											}}},
										},
									}}},
								},
							}}},
						},
					},
				},
			},
			Modified:  timestamppb.New(time.Date(2024, 5, 20, 16, 3, 47, 0, time.UTC)),
			Published: timestamppb.New(time.Date(2023, 5, 11, 18, 59, 56, 0, time.UTC)),
			Credits:   []*osvschema.Credit{{Name: "motoyasu-saburi"}},
			References: []*osvschema.Reference{
				{Type: osvschema.Reference_REPORT, Url: "https://github.com/gin-gonic/gin/issues/3555"},
				{Type: osvschema.Reference_FIX, Url: "https://github.com/gin-gonic/gin/pull/3556"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/gin-gonic/gin/releases/tag/v1.9.1"},
			},
		}

		jsVuln1 = osvschema.Vulnerability{
			SchemaVersion: "1.7.0",
			Id:            "GHSA-qw6h-vgh9-j6wx",
			Modified:      timestamppb.New(time.Date(2024, 11, 18, 16, 27, 11, 0, time.UTC)),
			Published:     timestamppb.New(time.Date(2024, 9, 10, 19, 41, 4, 0, time.UTC)),
			Aliases:       []string{"CVE-2024-43796"},
			Related:       []string{"CGA-7rmh-796c-qmq8", "CGA-8w92-879x-f9wc", "CGA-jq8v-jx6x-3fpc"},
			Summary:       "express vulnerable to XSS via response.redirect()",
			Details:       "In express <4.20.0, passing untrusted user input ...",
			Severity: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"},
				{Type: osvschema.Severity_CVSS_V4, Score: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L"},
			},
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Ecosystem: "npm", Name: "express", Purl: "pkg:npm/express"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "4.20.0"}}},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/09/GHSA-qw6h-vgh9-j6wx/GHSA-qw6h-vgh9-j6wx.json"}},
						},
					},
				},
				{
					Package: &osvschema.Package{Ecosystem: "npm", Name: "express", Purl: "pkg:npm/express"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "5.0.0-alpha.1"}, {Fixed: "5.0.0"}}},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/09/GHSA-qw6h-vgh9-j6wx/GHSA-qw6h-vgh9-j6wx.json"}},
						},
					},
				},
			},
			References: []*osvschema.Reference{
				{Type: osvschema.Reference_WEB, Url: "https://github.com/expressjs/express/security/advisories/GHSA-qw6h-vgh9-j6wx"},
				{Type: osvschema.Reference_ADVISORY, Url: "https://nvd.nist.gov/vuln/detail/CVE-2024-43796"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/expressjs/express/commit/54271f69b511fea198471e6ff3400ab805d6b553"},
				{Type: osvschema.Reference_PACKAGE, Url: "https://github.com/expressjs/express"},
			},
			DatabaseSpecific: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"cwe_ids": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
						{Kind: &structpb.Value_StringValue{StringValue: "CWE-79"}},
					}}}},
					"github_reviewed":    {Kind: &structpb.Value_BoolValue{BoolValue: true}},
					"github_reviewed_at": {Kind: &structpb.Value_StringValue{StringValue: "2024-09-10T19:41:04Z"}},
					"nvd_published_at":   {Kind: &structpb.Value_StringValue{StringValue: "2024-09-10T15:15:17Z"}},
					"severity":           {Kind: &structpb.Value_StringValue{StringValue: "LOW"}},
				},
			},
		}

		jsVuln1Local = osvschema.Vulnerability{
			SchemaVersion: "1.7.0",
			Id:            "GHSA-qw6h-vgh9-j6wx",
			Modified:      timestamppb.New(time.Date(2024, 11, 18, 16, 27, 11, 0, time.UTC)),
			Published:     timestamppb.New(time.Date(2024, 9, 10, 19, 41, 4, 0, time.UTC)),
			Aliases:       []string{"CVE-2024-43796"},
			Related:       []string{"CGA-7rmh-796c-qmq8", "CGA-8w92-879x-f9wc", "CGA-jq8v-jx6x-3fpc"},
			Summary:       "express vulnerable to XSS via response.redirect()",
			Details:       "In express <4.20.0, passing untrusted user input ...",
			Severity: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"},
			},
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Ecosystem: "npm", Name: "express", Purl: "pkg:npm/express"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "4.20.0"}}},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/09/GHSA-qw6h-vgh9-j6wx/GHSA-qw6h-vgh9-j6wx.json"}},
						},
					},
				},
				{
					Package: &osvschema.Package{Ecosystem: "npm", Name: "express", Purl: "pkg:npm/express"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "5.0.0-alpha.1"}, {Fixed: "5.0.0"}}},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/09/GHSA-qw6h-vgh9-j6wx/GHSA-qw6h-vgh9-j6wx.json"}},
						},
					},
				},
			},
		}

		jsVuln2 = osvschema.Vulnerability{
			SchemaVersion: "1.7.0",
			Id:            "GHSA-rv95-896h-c2vc",
			Modified:      timestamppb.New(time.Date(2025, 7, 21, 16, 57, 31, 0, time.UTC)),
			Published:     timestamppb.New(time.Date(2024, 3, 25, 19, 40, 26, 0, time.UTC)),
			Withdrawn:     timestamppb.New(time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)),
			Aliases:       []string{"CVE-2024-29041"},
			Related:       []string{"CGA-5389-98xc-vr78", "CGA-qg2p-wmx3-mx9q", "CGA-rjrm-49wc-v48x", "CGA-w26h-h47r-f6rx", "CVE-2024-29041"},
			Summary:       "Express.js Open Redirect in malformed URLs",
			Details:       "Versions of Express.js prior to 4.19.2 ...",
			Severity:      []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}},
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Ecosystem: "npm", Name: "express", Purl: "pkg:npm/express"},
					Ranges:  []*osvschema.Range{{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "4.19.2"}}}},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/03/GHSA-rv95-896h-c2vc/GHSA-rv95-896h-c2vc.json"}},
						},
					},
				},
				{
					Package: &osvschema.Package{Ecosystem: "npm", Name: "express", Purl: "pkg:npm/express"},
					Ranges:  []*osvschema.Range{{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "5.0.0-alpha.1"}, {Fixed: "5.0.0-beta.3"}}}},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/03/GHSA-rv95-896h-c2vc/GHSA-rv95-896h-c2vc.json"}},
						},
					}},
			},
			References: []*osvschema.Reference{
				{Type: osvschema.Reference_WEB, Url: "https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc"},
				{Type: osvschema.Reference_ADVISORY, Url: "https://nvd.nist.gov/vuln/detail/CVE-2024-29041"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/koajs/koa/issues/1800"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/expressjs/express/pull/5539"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/expressjs/express/commit/0867302ddbde0e9463d0564fea5861feb708c2dd"},
				{Type: osvschema.Reference_WEB, Url: "https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94"},
				{Type: osvschema.Reference_WEB, Url: "https://expressjs.com/en/4x/api.html#res.location"},
				{Type: osvschema.Reference_PACKAGE, Url: "https://github.com/expressjs/express"},
			},
			DatabaseSpecific: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"cwe_ids": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
						{Kind: &structpb.Value_StringValue{StringValue: "CWE-1286"}},
						{Kind: &structpb.Value_StringValue{StringValue: "CWE-601"}},
					}}}},
					"github_reviewed":    {Kind: &structpb.Value_BoolValue{BoolValue: true}},
					"github_reviewed_at": {Kind: &structpb.Value_StringValue{StringValue: "2024-03-25T19:40:26Z"}},
					"nvd_published_at":   {Kind: &structpb.Value_StringValue{StringValue: "2024-03-25T21:15:46Z"}},
					"severity":           {Kind: &structpb.Value_StringValue{StringValue: "MODERATE"}},
				},
			},
		}

		fzfVulnLocal = osvschema.Vulnerability{
			Id: "mockID",
			Affected: inventory.PackageToAffected(fzfPkg, "3002.1", &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			}),
		}

		pyPkgSameVulnAsFzf = osvschema.Vulnerability{
			Id: "mockID",
			Affected: inventory.PackageToAffected(pyPkg, "3.002.1", &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			}),
		}
	)

	client := fakeclient.New(map[string][]*osvschema.Vulnerability{
		fmt.Sprintf("%s:%s:", goPkg.Name, goPkg.Version): {&goVuln1, &goVuln2, &goVuln3},
		fmt.Sprintf("%s:%s:", jsPkg.Name, jsPkg.Version): {&jsVuln1, &jsVuln2},
		fmt.Sprintf("%s:%s:", pyPkg.Name, pyPkg.Version): {&pyPkgSameVulnAsFzf},
	})

	tests := []struct {
		name         string
		packageVulns []*inventory.PackageVuln
		packages     []*extractor.Package
		//nolint:containedctx
		ctx                 context.Context
		wantErr             error
		initialQueryTimeout time.Duration
		wantPackageVulns    []*inventory.PackageVuln
	}{
		{
			name:             "ctx_cancelled",
			ctx:              cancelledContext,
			packages:         []*extractor.Package{jsPkg, goPkg},
			wantPackageVulns: []*inventory.PackageVuln{},
			wantErr:          cmpopts.AnyError,
		},
		{
			name:                "initial_query_timeout",
			initialQueryTimeout: -1 * time.Second,
			packages:            []*extractor.Package{jsPkg, goPkg},
			wantPackageVulns:    []*inventory.PackageVuln{},
			wantErr:             osvdev.ErrInitialQueryTimeout,
		},
		{
			name:     "simple_test",
			packages: []*extractor.Package{goPkg},
			wantPackageVulns: []*inventory.PackageVuln{
				{Vulnerability: &goVuln1, Package: goPkg, Plugins: []string{osvdev.Name}},
				{Vulnerability: &goVuln2, Package: goPkg, Plugins: []string{osvdev.Name}},
				{Vulnerability: &goVuln3, Package: goPkg, Plugins: []string{osvdev.Name}},
			},
		},
		{
			name:             "not_covered_purl_type",
			packages:         []*extractor.Package{fzfPkg},
			wantPackageVulns: []*inventory.PackageVuln{},
		},
		{
			name:             "unknown_package",
			packages:         []*extractor.Package{unknownPkg},
			wantPackageVulns: []*inventory.PackageVuln{},
		},
		{
			name:     "interleaving_covered_not_covered",
			packages: []*extractor.Package{goPkg, fzfPkg, jsPkg},
			wantPackageVulns: []*inventory.PackageVuln{
				{Vulnerability: &goVuln1, Package: goPkg, Plugins: []string{osvdev.Name}},
				{Vulnerability: &goVuln2, Package: goPkg, Plugins: []string{osvdev.Name}},
				{Vulnerability: &goVuln3, Package: goPkg, Plugins: []string{osvdev.Name}},
				{Vulnerability: &jsVuln1, Package: jsPkg, Plugins: []string{osvdev.Name}},
				{Vulnerability: &jsVuln2, Package: jsPkg, Plugins: []string{osvdev.Name}},
			},
		},
		{
			name: "not_empty_local_inventory_vulns",
			packageVulns: []*inventory.PackageVuln{
				{Vulnerability: &fzfVulnLocal, Package: fzfPkg, Plugins: []string{"mock/plugin"}},
			},
			packages: []*extractor.Package{fzfPkg, jsPkg},
			wantPackageVulns: []*inventory.PackageVuln{
				{Vulnerability: &fzfVulnLocal, Package: fzfPkg, Plugins: []string{"mock/plugin"}},
				{Vulnerability: &jsVuln1, Package: jsPkg, Plugins: []string{osvdev.Name}},
				{Vulnerability: &jsVuln2, Package: jsPkg, Plugins: []string{osvdev.Name}},
			},
		},
		{
			name: "one_local_one_remote__same_pkg_same_cve",
			packageVulns: []*inventory.PackageVuln{
				{Vulnerability: &jsVuln1Local, Package: jsPkg, Plugins: []string{"mock/plugin"}},
			},
			packages: []*extractor.Package{jsPkg},
			wantPackageVulns: []*inventory.PackageVuln{
				{Vulnerability: &jsVuln1, Package: jsPkg, Plugins: []string{osvdev.Name, "mock/plugin"}},
				{Vulnerability: &jsVuln2, Package: jsPkg, Plugins: []string{osvdev.Name}},
			},
		},
		{
			name: "one_local_one_remote__different_pkg_same_cve",
			packageVulns: []*inventory.PackageVuln{
				{Vulnerability: &fzfVulnLocal, Package: fzfPkg, Plugins: []string{"mock/plugin"}},
			},
			packages: []*extractor.Package{fzfPkg, pyPkg},
			wantPackageVulns: []*inventory.PackageVuln{
				{Vulnerability: &fzfVulnLocal, Package: fzfPkg, Plugins: []string{"mock/plugin"}},
				{Vulnerability: &pyPkgSameVulnAsFzf, Package: pyPkg, Plugins: []string{osvdev.Name}},
			},
		},
		{
			name:     "exploitability_signals",
			packages: []*extractor.Package{goPkgWithSignals},
			wantPackageVulns: []*inventory.PackageVuln{
				{
					Vulnerability:         &goVuln1,
					Package:               goPkgWithSignals,
					Plugins:               []string{osvdev.Name},
					ExploitabilitySignals: []*vex.FindingExploitabilitySignal{{Plugin: "annotator/example", Justification: vex.Unspecified}},
				},
				{Vulnerability: &goVuln2, Package: goPkgWithSignals, Plugins: []string{osvdev.Name}},
				{Vulnerability: &goVuln3, Package: goPkgWithSignals, Plugins: []string{osvdev.Name}},
			}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = context.Background()
			}

			e := osvdev.NewWithClient(client, tt.initialQueryTimeout)

			var input *enricher.ScanInput

			if tt.packageVulns == nil {
				tt.packageVulns = []*inventory.PackageVuln{}
			}

			inv := &inventory.Inventory{
				PackageVulns: tt.packageVulns,
				Packages:     tt.packages,
			}

			err := e.Enrich(tt.ctx, input, inv)
			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Enrich(%v) error: %v, want %v", tt.packages, err, tt.wantErr)
			}

			want := &inventory.Inventory{
				PackageVulns: tt.wantPackageVulns,
				Packages:     tt.packages,
			}

			sortPkgVulns := cmpopts.SortSlices(func(a, b *inventory.PackageVuln) bool {
				if a.Vulnerability.Id != b.Vulnerability.Id {
					return a.Vulnerability.Id < b.Vulnerability.Id
				}
				return a.Package.Name < b.Package.Name
			})

			diff := cmp.Diff(
				want, inv,
				sortPkgVulns,
				protocmp.Transform(),
			)

			if diff != "" {
				t.Errorf("Enrich(%v): unexpected diff (-want +got): %v", tt.packages, diff)
			}
		})
	}
}
