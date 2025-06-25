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

package resolution_test

import (
	"context"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/resolve/schema"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/guidedremediation/internal/matchertest"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
)

func TestFindVulnerabilities(t *testing.T) {
	aliasType := func(knownAs string) dep.Type {
		var typ dep.Type
		typ.AddAttr(dep.KnownAs, knownAs)
		return typ
	}
	m := mockManifest{
		name:    "test",
		version: "1.0.0",
		system:  resolve.NPM,
		requirements: []mockManifestRequirements{
			{
				name:    "alice",
				version: "^1.0.0",
			},
			{
				name:    "alice",
				version: "^2.0.0",
				typ:     aliasType("charlie"),
			},
			{
				name:    "bob",
				version: "*",
			},
		},
	}
	m.groups = map[manifest.RequirementKey][]string{
		npm.MakeRequirementKey(m.Requirements()[0]): {"dev"},
		npm.MakeRequirementKey(m.Requirements()[2]): {"dev"},
	}

	g, err := schema.ParseResolve(`
test 1.0.0
	alice@^1.0.0 1.0.0
		$c@^2.0.1
	KnownAs charlie | alice@^2.0.0 2.0.1
	bob@* 1.0.0
		c: charlie@^2.0.0 2.0.1
`, resolve.NPM)
	if err != nil {
		t.Fatal(err)
	}
	const (
		// Parsing the above graph should map packages to these nodes.
		testNode    resolve.NodeID = 0
		aliceV1Node resolve.NodeID = 1
		aliceV2Node resolve.NodeID = 2
		bobNode     resolve.NodeID = 3
		charlieNode resolve.NodeID = 4
	)

	vulnMatcher := matchertest.NewMockVulnerabilityMatcher(t, "testdata/vulnerabilities.yaml")
	type vuln struct {
		ID    string
		Nodes []resolve.NodeID
	}
	want := []vuln{
		{
			ID: "VULN-000",
			Nodes: []resolve.NodeID{
				aliceV1Node,
				aliceV2Node,
			},
		},
		{
			ID: "VULN-001",
			Nodes: []resolve.NodeID{
				aliceV1Node,
			},
		},
		{
			ID: "VULN-002",
			Nodes: []resolve.NodeID{
				charlieNode,
			},
		},
		{
			ID: "VULN-003",
			Nodes: []resolve.NodeID{
				bobNode,
				charlieNode,
			},
		},
	}

	vulns, err := resolution.FindVulnerabilities(context.Background(), vulnMatcher, m.Groups(), g)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]vuln, len(vulns))
	for i, v := range vulns {
		got[i].ID = v.OSV.ID
		for _, sg := range v.Subgraphs {
			got[i].Nodes = append(got[i].Nodes, sg.Dependency)
		}
	}

	cmpOpts := []cmp.Option{
		cmpopts.SortSlices(func(a, b vuln) bool { return a.ID < b.ID }),
		cmpopts.SortSlices(func(a, b resolve.NodeID) bool { return a < b }),
	}

	if diff := cmp.Diff(want, got, cmpOpts...); diff != "" {
		t.Errorf("FindVulnerabilities() mismatch (-want +got):\n%s", diff)
	}
}
