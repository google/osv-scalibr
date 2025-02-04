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

// Package resolution provides dependency graph resolution and vulnerability findings
// for guided remediation.
package resolution

import (
	"context"
	"slices"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/internal/guidedremediation/client"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Vulnerability represents a vulnerability found in a dependency graph.
type Vulnerability struct {
	OSV     *client.OSVRecord
	DevOnly bool
	// Subgraphs are the collections of nodes and edges that reach the vulnerable node.
	// Subgraphs all contain the root node (NodeID 0) with no incoming edges (Parents),
	// and the vulnerable node (NodeID DependencySubgraph.Dependency) with no outgoing edges (Children).
	Subgraphs []*DependencySubgraph
}

// FindVulnerabilities scans for vulnerabilities in a resolved graph.
// One Vulnerability is created per unique ID, which may affect multiple graph nodes.
func FindVulnerabilities(ctx context.Context, cl client.VulnerabilityMatcher, m manifest.Manifest, graph *resolve.Graph) ([]Vulnerability, error) {
	nodeVulns, err := cl.MatchVulnerabilities(ctx, graphToInventory(graph))
	if err != nil {
		return nil, err
	}

	// The root node is of the graph is excluded from the vulnerability results.
	// Prepend an element to nodeVulns so that the indices line up with graph.Nodes[i] <=> nodeVulns[i]
	nodeVulns = append([][]*client.OSVRecord{nil}, nodeVulns...)

	// Find the dependency subgraphs of the vulnerable dependencies.
	var vulnerableNodes []resolve.NodeID
	uniqueVulns := make(map[string]*client.OSVRecord)
	for i, vulns := range nodeVulns {
		if len(vulns) > 0 {
			vulnerableNodes = append(vulnerableNodes, resolve.NodeID(i))
		}
		for _, vuln := range vulns {
			uniqueVulns[vuln.ID] = vuln
		}
	}

	nodeSubgraphs := ComputeSubgraphs(graph, vulnerableNodes)
	vulnSubgraphs := make(map[string][]*DependencySubgraph)
	for i, nID := range vulnerableNodes {
		for _, vuln := range nodeVulns[nID] {
			vulnSubgraphs[vuln.ID] = append(vulnSubgraphs[vuln.ID], nodeSubgraphs[i])
		}
	}

	// Construct the Vulnerabilities
	vulns := make([]Vulnerability, 0, len(uniqueVulns))
	for id, vuln := range uniqueVulns {
		vuln := Vulnerability{OSV: vuln, DevOnly: true}
		vuln.Subgraphs = vulnSubgraphs[id]
		vuln.DevOnly = !slices.ContainsFunc(vuln.Subgraphs, func(ds *DependencySubgraph) bool { return !ds.IsDevOnly(m.Groups()) })
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// graphToInventory is a helper function to convert a Graph into an Inventory for use with VulnerabilityMatcher.
func graphToInventory(g *resolve.Graph) []*extractor.Inventory {
	// g.Nodes[0] is the root node of the graph that should be excluded.
	inv := make([]*extractor.Inventory, len(g.Nodes)-1)
	for i, n := range g.Nodes[1:] {
		inv[i] = &extractor.Inventory{
			Name:      n.Version.Name,
			Version:   n.Version.Version,
			Extractor: mockExtractor{n.Version.System},
		}
	}

	return inv
}

// mockExtractor is for graphToInventory to get the ecosystem.
type mockExtractor struct {
	ecosystem resolve.System
}

func (e mockExtractor) Ecosystem(*extractor.Inventory) string {
	switch e.ecosystem {
	case resolve.NPM:
		return "npm"
	case resolve.Maven:
		return "Maven"
	case resolve.UnknownSystem:
		return ""
	default:
		return ""
	}
}

func (e mockExtractor) Name() string                                 { return "" }
func (e mockExtractor) Requirements() *plugin.Capabilities           { return nil }
func (e mockExtractor) ToPURL(*extractor.Inventory) *purl.PackageURL { return nil }
func (e mockExtractor) Version() int                                 { return 0 }
