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

package spdx_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/converter/spdx"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

const testNS = "https://spdx.google/test"

func iri(localID string) string {
	return testNS + "/" + localID
}

func element(localID, typ, name string) spdx.Element3 {
	return spdx.Element3{
		SPDXID:       iri(localID),
		Type:         typ,
		Name:         name,
		CreationInfo: "_:creationInfo_0",
	}
}

func licenseExpr(expr string) *spdx.LicenseExpression3 {
	return &spdx.LicenseExpression3{
		Element3:          element(spdx.SPDXRefPrefix+"LicenseExpression-"+strings.NewReplacer(" ", "-", "(", "-", ")", "-").Replace(expr), spdx.TypeLicenseExpression, ""),
		LicenseExpression: expr,
	}
}

func relationship(n int, from, relType string, to ...string) *spdx.Relationship3 {
	toIRIs := make([]string, 0, len(to))
	for _, t := range to {
		toIRIs = append(toIRIs, iri(t))
	}
	return &spdx.Relationship3{
		Element3:         element(fmt.Sprintf("%sRelationship-%d", spdx.SPDXRefPrefix, n), spdx.TypeRelationship, ""),
		From:             iri(from),
		To:               toIRIs,
		RelationshipType: relType,
	}
}

func scalibrAgent() *spdx.Element3 {
	e := element(spdx.SPDXRefPrefix+"Agent-SCALIBR", spdx.TypeSoftwareAgent, "SCALIBR")
	return &e
}

func mainPackage(id string) *spdx.Package3 {
	return &spdx.Package3{
		Element3:       element(spdx.SPDXRefPrefix+"Package-main-"+id, spdx.TypePackage, "main"),
		PackageVersion: "0",
	}
}

func TestToSPDX30(t *testing.T) {
	// Make UUIDs deterministic.
	uuid.SetRand(rand.New(rand.NewSource(1)))

	testCases := []struct {
		desc string
		inv  inventory.Inventory
		want []any
	}{
		{
			desc: "single_package",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "software",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Plugins:  []string{wheelegg.Name},
				}},
			},
			want: []any{
				scalibrAgent(),
				licenseExpr("CC0-1.0"),
				licenseExpr("NOASSERTION"),
				mainPackage("52fdfc07-2182-454f-963f-5f0f9a621d72"),
				&spdx.Package3{
					Element3: func() spdx.Element3 {
						e := element(spdx.SPDXRefPrefix+"Package-software-9566c74d-1003-4c4d-bbbb-0407d1e2c649", spdx.TypePackage, "software")
						e.ExternalIdentifier = []spdx.ExternalIdentifier3{{
							Type:                   spdx.TypeExternalIdentifier,
							ExternalIdentifierType: "packageUrl",
							Identifier:             "pkg:pypi/software@1.2.3",
						}}
						return e
					}(),
					PackageVersion: "1.2.3",
					PackageURL:     "pkg:pypi/software@1.2.3",
					SourceInfo:     "Identified by the python/wheelegg extractor",
				},
				relationship(1, spdx.SPDXDocumentID, spdx.RelDescribes, spdx.SPDXRefPrefix+"Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72"),
				relationship(2, spdx.SPDXRefPrefix+"Package-software-9566c74d-1003-4c4d-bbbb-0407d1e2c649", spdx.RelHasConcludedLicense, spdx.SPDXRefPrefix+"LicenseExpression-NOASSERTION"),
				relationship(3, spdx.SPDXRefPrefix+"Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72", spdx.RelContains, spdx.SPDXRefPrefix+"Package-software-9566c74d-1003-4c4d-bbbb-0407d1e2c649"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := converter.ToSPDX30(tc.inv, spdx.Config3{DocumentNamespace: testNS})
			if got.Context != spdx.SPDX3Context {
				t.Errorf("context = %q, want %q", got.Context, spdx.SPDX3Context)
			}
			// The first two elements are checked separately: the creation timestamp can't be mocked
			// and the document element just references the rest of the graph.
			ci, ok := got.Graph[0].(*spdx.CreationInfo3)
			if !ok {
				t.Fatalf("graph[0] is %T, want *spdx.CreationInfo3", got.Graph[0])
			}
			wantCI := &spdx.CreationInfo3{
				ID:          "_:creationInfo_0",
				Type:        spdx.TypeCreationInfo,
				SpecVersion: spdx.SPDX3Version,
				Created:     ci.Created,
				CreatedBy:   []string{iri(spdx.SPDXRefPrefix + "Agent-SCALIBR")},
			}
			if diff := cmp.Diff(wantCI, ci); diff != "" {
				t.Errorf("creation info: unexpected diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.want, got.Graph[2:]); diff != "" {
				t.Errorf("converter.ToSPDX30(%v): unexpected diff (-want +got):\n%s", tc.inv, diff)
			}
		})
	}
}

func TestToSPDX30_Document(t *testing.T) {
	uuid.SetRand(rand.New(rand.NewSource(1)))

	got := converter.ToSPDX30(inventory.Inventory{}, spdx.Config3{
		DocumentName:      "my-doc",
		DocumentNamespace: testNS,
		Creators: []common.Creator{
			{CreatorType: "Person", Creator: "Alice"},
			{CreatorType: "Organization", Creator: "Acme"},
			{CreatorType: "Tool", Creator: "some-tool"},
		},
	})

	doc, ok := got.Graph[1].(*spdx.SpdxDocument3)
	if !ok {
		t.Fatalf("graph[1] is %T, want *spdx.SpdxDocument3", got.Graph[1])
	}
	want := &spdx.SpdxDocument3{
		Element3:           element(spdx.SPDXDocumentID, spdx.TypeSpdxDocument, "my-doc"),
		DataLicense:        iri(spdx.SPDXRefPrefix + "LicenseExpression-CC0-1.0"),
		RootElement:        []string{iri(spdx.SPDXRefPrefix + "Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72")},
		ProfileConformance: []string{"core", "software"},
	}
	if diff := cmp.Diff(want, doc); diff != "" {
		t.Errorf("document: unexpected diff (-want +got):\n%s", diff)
	}

	ci := got.Graph[0].(*spdx.CreationInfo3)
	wantCreatedBy := []string{
		iri(spdx.SPDXRefPrefix + "Agent-SCALIBR"),
		iri(spdx.SPDXRefPrefix + "Agent-0-Alice"),
		iri(spdx.SPDXRefPrefix + "Agent-1-Acme"),
	}
	if diff := cmp.Diff(wantCreatedBy, ci.CreatedBy); diff != "" {
		t.Errorf("createdBy: unexpected diff (-want +got):\n%s", diff)
	}
	wantCreatedUsing := []string{iri(spdx.SPDXRefPrefix + "Agent-2-some-tool")}
	if diff := cmp.Diff(wantCreatedUsing, ci.CreatedUsing); diff != "" {
		t.Errorf("createdUsing: unexpected diff (-want +got):\n%s", diff)
	}

	wantAgents := []any{
		scalibrAgent(),
		&spdx.Element3{SPDXID: iri(spdx.SPDXRefPrefix + "Agent-0-Alice"), Type: spdx.TypePerson, Name: "Alice", CreationInfo: "_:creationInfo_0"},
		&spdx.Element3{SPDXID: iri(spdx.SPDXRefPrefix + "Agent-1-Acme"), Type: spdx.TypeOrganization, Name: "Acme", CreationInfo: "_:creationInfo_0"},
		&spdx.Element3{SPDXID: iri(spdx.SPDXRefPrefix + "Agent-2-some-tool"), Type: spdx.TypeTool, Name: "some-tool", CreationInfo: "_:creationInfo_0"},
	}
	if diff := cmp.Diff(wantAgents, got.Graph[2:6]); diff != "" {
		t.Errorf("agents: unexpected diff (-want +got):\n%s", diff)
	}
}

func TestToSPDX30_DefaultNameAndNamespace(t *testing.T) {
	uuid.SetRand(rand.New(rand.NewSource(1)))

	got := converter.ToSPDX30(inventory.Inventory{}, spdx.Config3{})
	doc := got.Graph[1].(*spdx.SpdxDocument3)
	if doc.Name != "SCALIBR-generated SPDX" {
		t.Errorf("document name = %q, want %q", doc.Name, "SCALIBR-generated SPDX")
	}
	if !strings.HasPrefix(doc.SPDXID, "https://spdx.google/") {
		t.Errorf("document spdxId = %q, want a https://spdx.google/ IRI", doc.SPDXID)
	}
	if !strings.HasSuffix(doc.SPDXID, "/"+spdx.SPDXDocumentID) {
		t.Errorf("document spdxId = %q, want it to end in /%s", doc.SPDXID, spdx.SPDXDocumentID)
	}
}

// relTriples projects the relationship elements of doc into "from -type-> to" strings with the
// document namespace stripped, so that graph shape can be asserted without spelling out full IRIs.
func relTriples(doc *spdx.Document3) []string {
	var triples []string
	for _, e := range doc.Graph {
		r, ok := e.(*spdx.Relationship3)
		if !ok {
			continue
		}
		to := make([]string, 0, len(r.To))
		for _, t := range r.To {
			to = append(to, strings.TrimPrefix(t, testNS+"/"))
		}
		triples = append(triples, fmt.Sprintf("%s -%s-> %s", strings.TrimPrefix(r.From, testNS+"/"), r.RelationshipType, strings.Join(to, ",")))
	}
	return triples
}

func elementNames(doc *spdx.Document3, typ string) []string {
	var names []string
	for _, e := range doc.Graph {
		switch v := e.(type) {
		case *spdx.Package3:
			if v.Type == typ {
				names = append(names, v.Name)
			}
		case *spdx.File3:
			if v.Type == typ {
				names = append(names, v.Name)
			}
		case *spdx.CustomLicense3:
			if v.Type == typ {
				names = append(names, v.Name)
			}
		}
	}
	return names
}

func TestToSPDX30_Graph(t *testing.T) {
	uuid.SetRand(rand.New(rand.NewSource(1)))

	testCases := []struct {
		desc string
		inv  inventory.Inventory
		want []string
	}{
		{
			desc: "dependency_graph",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "parent", Version: "1.0.0", PURLType: purl.TypePyPi, ID: "parent-id"},
					{Name: "child", Version: "2.0.0", PURLType: purl.TypePyPi, ID: "child-id", ParentIDs: map[string]bool{"parent-id": true}},
				},
			},
			want: []string{
				"SPDXRef-DOCUMENT -describes-> SPDXRef-Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72",
				"SPDXRef-Package-parent-parent-id -hasConcludedLicense-> SPDXRef-LicenseExpression-NOASSERTION",
				"SPDXRef-Package-child-child-id -hasConcludedLicense-> SPDXRef-LicenseExpression-NOASSERTION",
				"SPDXRef-Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72 -contains-> SPDXRef-Package-parent-parent-id",
				"SPDXRef-Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72 -contains-> SPDXRef-Package-child-child-id",
				"SPDXRef-Package-parent-parent-id -dependsOn-> SPDXRef-Package-child-child-id",
			},
		},
		{
			desc: "unknown_parent_is_skipped",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "child", Version: "2.0.0", PURLType: purl.TypePyPi, ID: "child-id", ParentIDs: map[string]bool{"root": true, "missing": true}},
				},
			},
			want: []string{
				"SPDXRef-DOCUMENT -describes-> SPDXRef-Package-main-9566c74d-1003-4c4d-bbbb-0407d1e2c649",
				"SPDXRef-Package-child-child-id -hasConcludedLicense-> SPDXRef-LicenseExpression-NOASSERTION",
				"SPDXRef-Package-main-9566c74d-1003-4c4d-bbbb-0407d1e2c649 -contains-> SPDXRef-Package-child-child-id",
			},
		},
		{
			desc: "dependency_manifest_is_shared_between_packages",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "a", Version: "1.0.0", PURLType: purl.TypePyPi, ID: "a-id", Location: extractor.PackageLocation{Descriptor: &location.Location{File: &location.File{Path: "req.txt"}}}},
					{Name: "b", Version: "1.0.0", PURLType: purl.TypePyPi, ID: "b-id", Location: extractor.PackageLocation{Descriptor: &location.Location{File: &location.File{Path: "req.txt"}}}},
				},
			},
			want: []string{
				"SPDXRef-DOCUMENT -describes-> SPDXRef-Package-main-81855ad8-681d-4d86-91e9-1e00167939cb",
				"SPDXRef-Package-a-a-id -hasConcludedLicense-> SPDXRef-LicenseExpression-NOASSERTION",
				"SPDXRef-Package-b-b-id -hasConcludedLicense-> SPDXRef-LicenseExpression-NOASSERTION",
				"SPDXRef-Package-main-81855ad8-681d-4d86-91e9-1e00167939cb -contains-> SPDXRef-Package-a-a-id",
				"SPDXRef-Package-a-a-id -hasDependencyManifest-> SPDXRef-File-req.txt-e2ba4b93",
				"SPDXRef-Package-main-81855ad8-681d-4d86-91e9-1e00167939cb -contains-> SPDXRef-Package-b-b-id",
				"SPDXRef-Package-b-b-id -hasDependencyManifest-> SPDXRef-File-req.txt-e2ba4b93",
			},
		},
		{
			desc: "vendored_package_descends_from_source",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:       "libfuse",
						Version:    "1.0.0",
						PURLType:   purl.TypePyPi,
						ID:         "libfuse-id",
						SourceCode: &extractor.SourceCodeIdentifier{Repo: "https://github.com/libfuse/libfuse", Commit: "033844748010a3b8265bf1c90b9ae8ffe4cd9ca7"},
					},
				},
			},
			want: []string{
				"SPDXRef-DOCUMENT -describes-> SPDXRef-Package-main-6694d2c4-22ac-4208-a007-2939487f6999",
				"SPDXRef-Package-libfuse-libfuse-id -hasConcludedLicense-> SPDXRef-LicenseExpression-NOASSERTION",
				"SPDXRef-Package-main-6694d2c4-22ac-4208-a007-2939487f6999 -contains-> SPDXRef-Package-libfuse-libfuse-id",
				"SPDXRef-Package-libfuse-libfuse-id -descendantOf-> SPDXRef-Package-libfuse-libfuse-033844748010a3b8265bf1c90b9ae8ffe4cd9ca7",
			},
		},
		{
			desc: "packages_without_a_usable_purl_are_skipped",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "no-version", PURLType: purl.TypePyPi, ID: "a-id"},
					{Name: "no-purl-type", Version: "1.0.0", ID: "b-id"},
					{Name: "ok", Version: "1.0.0", PURLType: purl.TypePyPi, ID: "c-id"},
				},
			},
			want: []string{
				"SPDXRef-DOCUMENT -describes-> SPDXRef-Package-main-eb9d18a4-4784-445d-87f3-c67cf22746e9",
				"SPDXRef-Package-ok-c-id -hasConcludedLicense-> SPDXRef-LicenseExpression-NOASSERTION",
				"SPDXRef-Package-main-eb9d18a4-4784-445d-87f3-c67cf22746e9 -contains-> SPDXRef-Package-ok-c-id",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := converter.ToSPDX30(tc.inv, spdx.Config3{DocumentNamespace: testNS})
			if diff := cmp.Diff(tc.want, relTriples(got)); diff != "" {
				t.Errorf("relationships: unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToSPDX30_Licenses(t *testing.T) {
	uuid.SetRand(rand.New(rand.NewSource(1)))

	inv := inventory.Inventory{
		Packages: []*extractor.Package{
			{Name: "a", Version: "1.0.0", PURLType: purl.TypePyPi, ID: "a-id", Licenses: []string{"MIT"}},
			{Name: "b", Version: "1.0.0", PURLType: purl.TypePyPi, ID: "b-id", Licenses: []string{"MIT"}},
			{Name: "c", Version: "1.0.0", PURLType: purl.TypePyPi, ID: "c-id", Licenses: []string{"Some Custom License"}},
		},
	}
	got := converter.ToSPDX30(inv, spdx.Config3{DocumentNamespace: testNS})

	var exprs []string
	var customIDToURI []spdx.DictionaryEntry3
	for _, e := range got.Graph {
		if l, ok := e.(*spdx.LicenseExpression3); ok {
			exprs = append(exprs, l.LicenseExpression)
			customIDToURI = append(customIDToURI, l.CustomIDToURI...)
		}
	}
	// The LicenseRef- id in the expression resolves to the CustomLicense element holding its text.
	wantCustomIDToURI := []spdx.DictionaryEntry3{{
		Type:  spdx.TypeDictionaryEntry,
		Key:   "LicenseRef-Some-Custom-License",
		Value: iri("LicenseRef-Some-Custom-License"),
	}}
	if diff := cmp.Diff(wantCustomIDToURI, customIDToURI); diff != "" {
		t.Errorf("customIdToUri: unexpected diff (-want +got):\n%s", diff)
	}
	// MIT is emitted once and shared by both packages that declare it.
	wantExprs := []string{"CC0-1.0", "MIT", "LicenseRef-Some-Custom-License"}
	if diff := cmp.Diff(wantExprs, exprs); diff != "" {
		t.Errorf("license expressions: unexpected diff (-want +got):\n%s", diff)
	}

	var custom []*spdx.CustomLicense3
	for _, e := range got.Graph {
		if l, ok := e.(*spdx.CustomLicense3); ok {
			custom = append(custom, l)
		}
	}
	wantCustom := []*spdx.CustomLicense3{{
		Element3:    element("LicenseRef-Some-Custom-License", spdx.TypeCustomLicense, "LicenseRef-Some-Custom-License"),
		LicenseText: "Some Custom License",
	}}
	if diff := cmp.Diff(wantCustom, custom); diff != "" {
		t.Errorf("custom licenses: unexpected diff (-want +got):\n%s", diff)
	}
}
