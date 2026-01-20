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
	"errors"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/vulns"
	"github.com/google/osv-scalibr/inventory"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Vulnerability represents a vulnerability found in a dependency graph.
type Vulnerability struct {
	OSV     *osvpb.Vulnerability
	DevOnly bool
	// Subgraphs are the collections of nodes and edges that reach the vulnerable node.
	// Subgraphs all contain the root node (NodeID 0) with no incoming edges (Parents),
	// and the vulnerable node (NodeID DependencySubgraph.Dependency) with no outgoing edges (Children).
	Subgraphs []*DependencySubgraph
}

// FindVulnerabilities scans for vulnerabilities in a resolved graph.
// One Vulnerability is created per unique ID, which may affect multiple graph nodes.
func FindVulnerabilities(ctx context.Context, en enricher.Enricher, depGroups map[manifest.RequirementKey][]string, graph *resolve.Graph) ([]Vulnerability, error) {
	if en == nil || !strings.HasPrefix(en.Name(), "vulnmatch/") {
		return nil, errors.New("vulnmatch/ enricher is required")
	}

	// vulnmatch/ enrichers (so far) do not require ScanInput.
	inv, pkgsToNodes := graphToInventory(graph)
	if err := en.Enrich(ctx, nil, inv); err != nil {
		return nil, err
	}

	// The root node is of the graph is excluded from the inventory.
	// So we need to prepend a nil slice to nodeVulns so that the indices line up with graph.Nodes[i] <=> nodeVulns[i]
	nodeVulns := make([][]*osvpb.Vulnerability, len(graph.Nodes))
	for _, pVuln := range inv.PackageVulns {
		for _, nID := range pkgsToNodes[pVuln.Package] {
			nodeVulns[nID] = append(nodeVulns[nID], pVuln.Vulnerability)
		}
	}

	// Find the dependency subgraphs of the vulnerable dependencies.
	var vulnerableNodes []resolve.NodeID
	uniqueVulns := make(map[string]*osvpb.Vulnerability)
	for i, vulns := range nodeVulns {
		if len(vulns) > 0 {
			vulnerableNodes = append(vulnerableNodes, resolve.NodeID(i))
		}
		for _, vuln := range vulns {
			uniqueVulns[vuln.Id] = vuln
		}
	}

	nodeSubgraphs := ComputeSubgraphs(graph, vulnerableNodes)
	vulnSubgraphs := make(map[string][]*DependencySubgraph)
	for i, nID := range vulnerableNodes {
		for _, vuln := range nodeVulns[nID] {
			vulnSubgraphs[vuln.Id] = append(vulnSubgraphs[vuln.Id], nodeSubgraphs[i])
		}
	}

	// Construct the Vulnerabilities
	vulns := make([]Vulnerability, 0, len(uniqueVulns))
	for id, vuln := range uniqueVulns {
		vuln := Vulnerability{OSV: vuln, DevOnly: true}
		vuln.Subgraphs = vulnSubgraphs[id]
		vuln.DevOnly = !slices.ContainsFunc(vuln.Subgraphs, func(ds *DependencySubgraph) bool { return !ds.IsDevOnly(depGroups) })
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// packageKey is a map key for uniquely identifying a package by its name and version.
type packageKey struct {
	name    string
	version string
}

// graphToInventory is a helper function to convert a Graph into an Inventory for use with Enrichers.
// It also returns a map of packages to the graph nodes that they were found at.
func graphToInventory(g *resolve.Graph) (*inventory.Inventory, map[*extractor.Package][]resolve.NodeID) {
	// Inventories / packages expect unique packages, so we need to keep track of which are duplicates
	// (e.g. multiple versions of the same package in npm)
	uniquePkgs := make(map[packageKey]*extractor.Package)
	pkgsToNodes := make(map[*extractor.Package][]resolve.NodeID)
	// g.Nodes[0] is the root node of the graph that should be excluded.
	pkgs := make([]*extractor.Package, 0, len(g.Nodes)-1)
	for i, n := range g.Nodes[1:] {
		checkPkg := vulns.VKToPackage(n.Version)
		var pkg *extractor.Package
		var ok bool
		key := packageKey{name: checkPkg.Name, version: checkPkg.Version}
		if pkg, ok = uniquePkgs[key]; !ok {
			pkg = checkPkg
			uniquePkgs[key] = pkg
			pkgs = append(pkgs, pkg)
		}
		pkgsToNodes[pkg] = append(pkgsToNodes[pkg], resolve.NodeID(i+1))
	}

	return &inventory.Inventory{Packages: pkgs}, pkgsToNodes
}
