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

package internal_test

import (
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher/transitivedependency/internal"
	"github.com/google/osv-scalibr/enricher/transitivedependency/mockidgenerator"
	"github.com/google/osv-scalibr/extractor"
)

func TestGetNameToIDMapping(t *testing.T) {
	testcases := []struct {
		name         string
		nodes        []resolve.VersionKey
		packages     []*extractor.Package
		wantMapping  map[string]string
		wantPackages []*extractor.Package
	}{
		{
			name:         "empty",
			nodes:        []resolve.VersionKey{},
			packages:     []*extractor.Package{},
			wantMapping:  map[string]string{},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "known_packages",
			nodes: []resolve.VersionKey{
				{
					PackageKey: resolve.PackageKey{
						Name: "rootPackage",
					},
				},
			},
			packages: []*extractor.Package{
				{
					Name:    "org.direct:alice",
					ID:      "id-for-alice",
					Version: "1.0.0",
				},
				{
					Name:    "org.direct:bob",
					Version: "2.0.0",
				},
			},
			wantMapping: map[string]string{
				"org.direct:alice": "id-for-alice",
				"org.direct:bob":   "dummy-id-org.direct:bob",
			},
			wantPackages: []*extractor.Package{
				{
					Name:    "org.direct:alice",
					ID:      "id-for-alice",
					Version: "1.0.0",
				},
				{
					Name:    "org.direct:bob",
					ID:      "dummy-id-org.direct:bob",
					Version: "2.0.0",
				},
			},
		},
		{
			name: "unknown_packages",
			nodes: []resolve.VersionKey{
				{
					PackageKey: resolve.PackageKey{
						Name: "rootPackage",
					},
				},
				{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.direct:alice",
					},
					VersionType: resolve.Concrete,
					Version:     "1.0.0",
				},
				{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.direct:bob",
					},
					VersionType: resolve.Concrete,
					Version:     "2.0.0",
				},
			},
			packages: []*extractor.Package{},
			wantMapping: map[string]string{
				"org.direct:alice": "dummy-id-org.direct:alice",
				"org.direct:bob":   "dummy-id-org.direct:bob",
			},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "duplicate_package",
			nodes: []resolve.VersionKey{
				{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.direct:alice",
					},
					VersionType: resolve.Concrete,
					Version:     "1.0.0",
				},
				{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.direct:bob",
					},
					VersionType: resolve.Concrete,
					Version:     "2.0.0",
				},
			},
			packages: []*extractor.Package{
				{
					Name:    "org.direct:alice",
					ID:      "id-for-alice",
					Version: "1.0.0",
				},
				{
					Name:    "org.direct:bob",
					Version: "2.0.0",
				},
			},
			wantMapping: map[string]string{
				"org.direct:alice": "id-for-alice",
				"org.direct:bob":   "dummy-id-org.direct:bob",
			},
			wantPackages: []*extractor.Package{
				{
					Name:    "org.direct:alice",
					ID:      "id-for-alice",
					Version: "1.0.0",
				},
				{
					Name:    "org.direct:bob",
					ID:      "dummy-id-org.direct:bob",
					Version: "2.0.0",
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			graph := &resolve.Graph{
				Nodes: []resolve.Node{},
			}
			for _, n := range tc.nodes {
				graph.AddNode(n)
			}

			gotMapping, err := internal.GetNameToIDMapping(graph, tc.packages, &mockidgenerator.MockIDGenerator{})
			if err != nil {
				t.Errorf("GetNameToIDMapping(%v, %v) returned unexpected error: %v", tc.nodes, tc.packages, err)
			}
			if diff := cmp.Diff(tc.wantMapping, gotMapping); diff != "" {
				t.Errorf("GetNameToIDMapping(%v, %v) returned unexpected diff (-want +got):\n%s", tc.nodes, tc.packages, diff)
			}
			// GetNameToIDMapping can add IDs to packages so we need to check the
			// resulting packages too.
			if diff := cmp.Diff(tc.wantPackages, tc.packages); diff != "" {
				t.Errorf("GetNameToIDMapping(%v, %v) returned unexpected diff (-want +got):\n%s", tc.nodes, tc.packages, diff)
			}
		})
	}
}

func TestGetParentIDs(t *testing.T) {
	testcases := []struct {
		name        string
		nodes       []resolve.VersionKey
		edges       []resolve.Edge
		nameToID    map[string]string
		nodeID      resolve.NodeID
		wantParents map[string]bool
	}{
		{
			name:        "empty",
			nodes:       []resolve.VersionKey{},
			edges:       []resolve.Edge{},
			nameToID:    map[string]string{},
			nodeID:      0,
			wantParents: map[string]bool{},
		},
		{
			name: "direct_parent",
			nodes: []resolve.VersionKey{
				{
					PackageKey: resolve.PackageKey{
						Name: "",
					},
				},
				{
					PackageKey: resolve.PackageKey{
						Name: "package_a",
					},
				},
				{
					PackageKey: resolve.PackageKey{
						Name: "package_b",
					},
				},
			},
			edges: []resolve.Edge{
				{From: 0, To: 1},
				{From: 0, To: 2},
				{From: 1, To: 2},
			},
			nameToID: map[string]string{
				"package_a": "id-a",
				"package_b": "id-b",
			},
			nodeID:      1,
			wantParents: map[string]bool{"root": true},
		},
		{
			name: "transitive_parent",
			nodes: []resolve.VersionKey{
				{
					PackageKey: resolve.PackageKey{
						Name: "",
					},
				},
				{
					PackageKey: resolve.PackageKey{
						Name: "package_a",
					},
				},
				{
					PackageKey: resolve.PackageKey{
						Name: "package_b",
					},
				},
			},
			edges: []resolve.Edge{
				{From: 0, To: 1},
				{From: 0, To: 2},
				{From: 1, To: 2},
			},
			nameToID: map[string]string{
				"package_a": "id-a",
				"package_b": "id-b",
			},
			nodeID: 2,
			wantParents: map[string]bool{
				"root": true,
				"id-a": true,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			graph := &resolve.Graph{
				Nodes: []resolve.Node{},
			}
			for _, n := range tc.nodes {
				graph.AddNode(n)
			}
			for _, e := range tc.edges {
				if err := graph.AddEdge(e.From, e.To, e.Requirement, e.Type); err != nil {
					t.Errorf("AddEdge(%v, %v, %v, %v) returned unexpected error: %v", e.From, e.To, e.Requirement, e.Type, err)
				}
			}
			gotParents, err := internal.GetParentIDs(graph, tc.nameToID, tc.nodeID)
			if err != nil {
				t.Errorf("GetParentIDs(%v, %v, %v) returned unexpected error: %v", graph, tc.nameToID, tc.nodeID, err)
			}
			if diff := cmp.Diff(tc.wantParents, gotParents); diff != "" {
				t.Errorf("GetParentIDs(%v, %v, %v) returned unexpected diff (-want +got):\n%s", graph, tc.nameToID, tc.nodeID, diff)
			}
		})
	}
}
