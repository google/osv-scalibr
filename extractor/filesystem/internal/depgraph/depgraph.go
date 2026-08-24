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

// Package depgraph provides shared helpers for extractors that populate
// dependency graph edges (Package.ID and Package.ParentIDs).
package depgraph

import (
	"errors"

	"github.com/google/osv-scalibr/extractor"
)

// RootID is the ParentIDs sentinel that marks a package as a direct
// dependency of the scanned project. Converters map it to the SBOM's
// main package/component.
const RootID = "root"

// Edge is a resolved dependency relationship between two packages of an
// inventory. A nil Parent marks Child as a direct dependency of the
// scanned project.
type Edge struct {
	Parent *extractor.Package
	Child  *extractor.Package
}

// ApplyEdges assigns an ID to every package and populates ParentIDs from
// edges. Edges with an endpoint whose ID generation failed are dropped;
// those errors are joined in the returned error.
func ApplyEdges(packages []*extractor.Package, edges []Edge) error {
	withID, err := RequireIDs(packages)
	for _, e := range edges {
		if e.Child == nil || !withID[e.Child] {
			continue
		}
		switch {
		case e.Parent == nil:
			AddParent(e.Child, RootID)
		case withID[e.Parent]:
			AddParent(e.Child, e.Parent.ID)
		}
	}
	return err
}

// EdgesByName resolves dependency declarations to edges by package name.
// depsOf returns the dependency names declared by packages[i]; normalize
// maps names to their canonical form (nil for exact matching). A name
// borne by several packages produces an edge to each of them; names that
// match no package are dropped.
func EdgesByName(packages []*extractor.Package, depsOf func(i int) []string, normalize func(string) string) []Edge {
	norm := func(s string) string { return s }
	if normalize != nil {
		norm = normalize
	}
	byName := make(map[string][]*extractor.Package)
	for _, pkg := range packages {
		n := norm(pkg.Name)
		byName[n] = append(byName[n], pkg)
	}
	var edges []Edge
	for i, parent := range packages {
		for _, depName := range depsOf(i) {
			for _, child := range byName[norm(depName)] {
				if child != parent {
					edges = append(edges, Edge{Parent: parent, Child: child})
				}
			}
		}
	}
	return edges
}

// AddParent marks parentID as a parent of pkg, allocating ParentIDs if needed.
func AddParent(pkg *extractor.Package, parentID string) {
	if pkg.ParentIDs == nil {
		pkg.ParentIDs = map[string]bool{}
	}
	pkg.ParentIDs[parentID] = true
}

// RequireIDs assigns an ID to every package via Package.RequireID and returns
// the set of packages that received one. Packages whose ID generation failed
// are excluded from the set; their errors are joined in the returned error.
// Callers must only create edges between packages in the returned set.
func RequireIDs(packages []*extractor.Package) (map[*extractor.Package]bool, error) {
	withID := make(map[*extractor.Package]bool, len(packages))
	var errs []error
	for _, pkg := range packages {
		if _, err := pkg.RequireID(); err != nil {
			errs = append(errs, err)
			continue
		}
		withID[pkg] = true
	}
	return withID, errors.Join(errs...)
}
