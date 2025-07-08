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

// Package remediation has the vulnerability remediation implementations.
package remediation

import (
	"cmp"
	"context"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/matcher"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/internal/mavenutil"
)

// ResolvedGraph is a dependency graph and the vulnerabilities found in it.
type ResolvedGraph struct {
	Graph           *resolve.Graph
	Vulns           []resolution.Vulnerability
	UnfilteredVulns []resolution.Vulnerability
}

// ResolvedManifest is a manifest, its resolved dependency graph, and the vulnerabilities found in it.
type ResolvedManifest struct {
	ResolvedGraph

	Manifest manifest.Manifest
}

// ResolveManifest resolves and find vulnerabilities in a manifest.
func ResolveManifest(ctx context.Context, cl resolve.Client, vm matcher.VulnerabilityMatcher, m manifest.Manifest, opts *options.RemediationOptions) (*ResolvedManifest, error) {
	g, err := resolution.Resolve(ctx, cl, m, opts.ResolutionOptions)
	if err != nil {
		return nil, err
	}

	resGraph, err := ResolveGraphVulns(ctx, cl, vm, g, m.Groups(), opts)
	if err != nil {
		return nil, err
	}

	return &ResolvedManifest{
		Manifest:      m,
		ResolvedGraph: resGraph,
	}, nil
}

// ResolveGraphVulns finds the vulnerabilities in a graph.
func ResolveGraphVulns(ctx context.Context, cl resolve.Client, vm matcher.VulnerabilityMatcher, g *resolve.Graph, depGroups map[manifest.RequirementKey][]string, opts *options.RemediationOptions) (ResolvedGraph, error) {
	allVulns, err := resolution.FindVulnerabilities(ctx, vm, depGroups, g)
	if err != nil {
		return ResolvedGraph{}, err
	}

	// If explicit vulns are set, add the others to ignored vulns.
	if len(opts.ExplicitVulns) > 0 {
		for _, v := range allVulns {
			if !slices.Contains(opts.ExplicitVulns, v.OSV.ID) {
				opts.IgnoreVulns = append(opts.IgnoreVulns, v.OSV.ID)
			}
		}
	}

	filteredVulns := slices.Clone(allVulns)
	filteredVulns = slices.DeleteFunc(filteredVulns, func(v resolution.Vulnerability) bool { return !MatchVuln(*opts, v) })
	return ResolvedGraph{
		Graph:           g,
		Vulns:           filteredVulns,
		UnfilteredVulns: allVulns,
	}, nil
}

// ConstructPatches computes the effective Patches that were applied to oldRes to get newRes.
func ConstructPatches(oldRes, newRes *ResolvedManifest) result.Patch {
	fixedVulns := make(map[string]*resolution.Vulnerability)
	for _, v := range oldRes.Vulns {
		fixedVulns[v.OSV.ID] = &v
	}
	introducedVulns := make(map[string]*resolution.Vulnerability)
	for _, v := range newRes.Vulns {
		if _, ok := fixedVulns[v.OSV.ID]; !ok {
			introducedVulns[v.OSV.ID] = &v
		} else {
			delete(fixedVulns, v.OSV.ID)
		}
	}

	var output result.Patch
	output.Fixed = make([]result.Vuln, 0, len(fixedVulns))
	for _, v := range fixedVulns {
		vuln := result.Vuln{ID: v.OSV.ID}
		for _, sg := range v.Subgraphs {
			n := oldRes.Graph.Nodes[sg.Dependency]
			vuln.Packages = append(vuln.Packages, result.Package{Name: n.Version.Name, Version: n.Version.Version})
		}
		output.Fixed = append(output.Fixed, vuln)
	}
	slices.SortFunc(output.Fixed, func(a, b result.Vuln) int { return cmp.Compare(a.ID, b.ID) })

	if len(introducedVulns) > 0 {
		output.Introduced = make([]result.Vuln, 0, len(introducedVulns))
	}
	for _, v := range introducedVulns {
		vuln := result.Vuln{ID: v.OSV.ID}
		for _, sg := range v.Subgraphs {
			n := newRes.Graph.Nodes[sg.Dependency]
			vuln.Packages = append(vuln.Packages, result.Package{Name: n.Version.Name, Version: n.Version.Version})
		}
		output.Introduced = append(output.Introduced, vuln)
	}
	slices.SortFunc(output.Introduced, func(a, b result.Vuln) int { return cmp.Compare(a.ID, b.ID) })

	oldReqs := make(map[manifest.RequirementKey]resolve.RequirementVersion)
	for _, req := range oldRes.Manifest.Requirements() {
		oldReqs[resolution.MakeRequirementKey(req)] = req
	}
	for _, req := range newRes.Manifest.Requirements() {
		oldReq, ok := oldReqs[resolution.MakeRequirementKey(req)]
		if !ok {
			typ := dep.NewType()
			typ.AddAttr(dep.MavenDependencyOrigin, mavenutil.OriginManagement)
			output.PackageUpdates = append(output.PackageUpdates, result.PackageUpdate{
				Name:        req.Name,
				VersionFrom: "",
				VersionTo:   req.Version,
				Type:        typ,
				Transitive:  true,
			})
			continue
		}
		if req.Version == oldReq.Version {
			continue
		}

		// In Maven, a dependency can be in both <dependencies> and <dependencyManagement>.
		// To work out if this is direct or transitive, we need to check if this is appears the regular dependencies.
		direct := slices.ContainsFunc(oldRes.Manifest.Requirements(), func(r resolve.RequirementVersion) bool {
			if r.Name != req.Name {
				return false
			}
			origin, _ := r.Type.GetAttr(dep.MavenDependencyOrigin)
			return origin != mavenutil.OriginManagement
		})

		output.PackageUpdates = append(output.PackageUpdates, result.PackageUpdate{
			Name:        req.Name,
			VersionFrom: oldReq.Version,
			VersionTo:   req.Version,
			Type:        oldReq.Type.Clone(),
			Transitive:  !direct,
		})
	}
	cmpFn := func(a, b result.PackageUpdate) int {
		if c := cmp.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		if c := cmp.Compare(a.VersionFrom, b.VersionFrom); c != 0 {
			return c
		}
		if c := cmp.Compare(a.VersionTo, b.VersionTo); c != 0 {
			return c
		}
		return a.Type.Compare(b.Type)
	}
	slices.SortFunc(output.PackageUpdates, cmpFn)
	// It's possible something is in the requirements twice (e.g. with Maven dependencyManagement)
	// Deduplicate the patches in this case.
	output.PackageUpdates = slices.CompactFunc(output.PackageUpdates, func(a, b result.PackageUpdate) bool {
		return cmpFn(a, b) == 0
	})

	return output
}
