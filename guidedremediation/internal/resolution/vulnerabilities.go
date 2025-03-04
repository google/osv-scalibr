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

package resolution

import (
	"context"
	"slices"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/vulns"
	"github.com/google/osv-scalibr/guidedremediation/matcher"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Vulnerability represents a vulnerability found in a dependency graph.
type Vulnerability struct {
	OSV     *osvschema.Vulnerability
	DevOnly bool
	// Subgraphs are the collections of nodes and edges that reach the vulnerable node.
	// Subgraphs all contain the root node (NodeID 0) with no incoming edges (Parents),
	// and the vulnerable node (NodeID DependencySubgraph.Dependency) with no outgoing edges (Children).
	Subgraphs []*DependencySubgraph
}

// FindVulnerabilities scans for vulnerabilities in a resolved graph.
// One Vulnerability is created per unique ID, which may affect multiple graph nodes.
func FindVulnerabilities(ctx context.Context, cl matcher.VulnerabilityMatcher, m manifest.Manifest, graph *resolve.Graph) ([]Vulnerability, error) {
	nodeVulns, err := cl.MatchVulnerabilities(ctx, graphToPackage(graph))
	if err != nil {
		return nil, err
	}

	// The root node is of the graph is excluded from the vulnerability results.
	// Prepend an element to nodeVulns so that the indices line up with graph.Nodes[i] <=> nodeVulns[i]
	nodeVulns = append([][]*osvschema.Vulnerability{nil}, nodeVulns...)

	// Find the dependency subgraphs of the vulnerable dependencies.
	var vulnerableNodes []resolve.NodeID
	uniqueVulns := make(map[string]*osvschema.Vulnerability)
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

// graphToPackage is a helper function to convert a Graph into Packages for use with VulnerabilityMatcher.
func graphToPackage(g *resolve.Graph) []*extractor.Package {
	// g.Nodes[0] is the root node of the graph that should be excluded.
	pkg := make([]*extractor.Package, len(g.Nodes)-1)
	for i, n := range g.Nodes[1:] {
		pkg[i] = vulns.VKToPackage(n.Version)
	}

	return pkg
}
