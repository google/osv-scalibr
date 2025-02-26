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
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest"
)

// DependencySubgraph is a subgraph of dependencies that contains all paths to a specific node.
type DependencySubgraph struct {
	Dependency resolve.NodeID // The NodeID of the end dependency of this subgraph.
	Nodes      map[resolve.NodeID]GraphNode
}

// GraphNode is a node in a DependencySubgraph
type GraphNode struct {
	Version  resolve.VersionKey
	Distance int            // The shortest distance to the end Dependency Node (which has a Distance of 0)
	Parents  []resolve.Edge // Parent edges i.e. with Edge.To == this ID
	Children []resolve.Edge // Child edges i.e. with Edge.From == this ID
}

// ComputeSubgraphs computes the DependencySubgraphs for each specified NodeID.
// The computed Subgraphs contains all nodes and edges that transitively depend on the specified node, and the node itself.
//
// Modifying any of the returned DependencySubgraphs may cause unexpected behaviour.
func ComputeSubgraphs(g *resolve.Graph, nodes []resolve.NodeID) []*DependencySubgraph {
	// Find the parent nodes of each node in graph, for easier traversal.
	// These slices are shared between the returned subgraphs.
	parentEdges := make(map[resolve.NodeID][]resolve.Edge)
	for _, e := range g.Edges {
		// Check for a self-dependency, just in case.
		if e.From == e.To {
			continue
		}
		parentEdges[e.To] = append(parentEdges[e.To], e)
	}

	// For each node, compute the subgraph.
	subGraphs := make([]*DependencySubgraph, 0, len(nodes))
	for _, nodeID := range nodes {
		// Starting at the node of interest, visit all unvisited parents,
		// adding the corresponding edges to the GraphNodes.
		gNodes := make(map[resolve.NodeID]GraphNode)
		seen := make(map[resolve.NodeID]struct{})
		seen[nodeID] = struct{}{}
		toProcess := []resolve.NodeID{nodeID}
		currDistance := 0 // The current distance from end dependency.
		for len(toProcess) > 0 {
			// Track the next set of nodes to process, which will be +1 Distance away from end.
			var next []resolve.NodeID
			for _, node := range toProcess {
				// Construct the GraphNode
				parents := parentEdges[node]
				gNode := gNodes[node] // Grab the existing GraphNode, which will have some Children populated.
				gNode.Version = g.Nodes[node].Version
				gNode.Distance = currDistance
				gNode.Parents = parents
				gNodes[node] = gNode
				// Populate parent's children and add to next set.
				for _, edge := range parents {
					nID := edge.From
					pNode := gNodes[nID]
					pNode.Children = append(pNode.Children, edge)
					gNodes[nID] = pNode
					if _, ok := seen[nID]; !ok {
						seen[nID] = struct{}{}
						next = append(next, nID)
					}
				}
			}
			toProcess = next
			currDistance++
		}

		subGraphs = append(subGraphs, &DependencySubgraph{
			Dependency: nodeID,
			Nodes:      gNodes,
		})
	}

	return subGraphs
}

// IsDevOnly checks if this DependencySubgraph solely contains dev (or test) dependencies.
// If groups is nil, checks the dep.Type of the direct graph edges for the Dev Attr (for in-place).
// Otherwise, uses the groups of the direct dependencies to determine if a non-dev path exists (for relax/override).
func (ds *DependencySubgraph) IsDevOnly(groups map[manifest.RequirementKey][]string) bool {
	if groups != nil {
		// Check if any of the direct dependencies are not in the dev group.
		return !slices.ContainsFunc(ds.Nodes[0].Children, func(e resolve.Edge) bool {
			req := resolve.RequirementVersion{
				VersionKey: ds.Nodes[e.To].Version,
				Type:       e.Type.Clone(),
			}
			reqGroups := groups[MakeRequirementKey(req)]
			switch req.System {
			case resolve.NPM:
				return !slices.Contains(reqGroups, "dev")
			case resolve.Maven:
				return !slices.Contains(reqGroups, "test")
			default:
				return true
			}
		})
	}

	// groups == nil
	// Check if any of the direct dependencies do not have the Dev attr.
	for _, e := range ds.Nodes[0].Children {
		if e.Type.HasAttr(dep.Dev) {
			continue
		}
		// As a workaround for npm workspaces, check for the a Dev attr in the direct dependency's dependencies.
		for _, e2 := range ds.Nodes[e.To].Children {
			if !e2.Type.HasAttr(dep.Dev) {
				return false
			}
		}
		// If the vulnerable dependency is a direct dependency, it'd have no Children.
		// Since we've already checked that it doesn't have the Dev attr, it must be a non-dev dependency.
		if e.To == ds.Dependency {
			return false
		}
	}

	return true
}
