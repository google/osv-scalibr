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

// Package inplace implements the in-place remediation strategy.
package inplace

import (
	"cmp"
	"context"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/vulns"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scalibr/log"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// ComputePatches attempts to resolve each vulnerability found in the graph,
// returning the list of unique possible patches.
// Vulnerabilities are resolved by upgrading versions of vulnerable packages to compatible
// non-vulnerable versions. A version is compatible if it still satisfies the version constraints of
// all dependent packages, and its dependencies are satisfied by the existing graph.
func ComputePatches(ctx context.Context, cl resolve.Client, graph remediation.ResolvedGraph, opts *options.RemediationOptions) ([]result.Patch, error) {
	if len(graph.Graph.Nodes) == 0 {
		return nil, nil
	}
	sys := graph.Graph.Nodes[0].Version.Semver()
	requiredVersions := computeAllVersionConstraints(graph.Vulns, sys)
	type patch struct {
		vk    resolve.VersionKey
		vulns []*osvpb.Vulnerability
	}
	vkPatches := make(map[resolve.VersionKey][]patch)
	for _, v := range graph.Vulns {
		for _, sg := range v.Subgraphs {
			// Check if any of the existing patches fixes this vulnerability.
			vk := sg.Nodes[sg.Dependency].Version
			if opts.UpgradeConfig.Get(vk.Name) == upgrade.None {
				// Don't try to fix vulns in packages that aren't allowed to be upgraded.
				continue
			}
			foundFix := false
			for i, p := range vkPatches[vk] {
				if !vulns.IsAffected(v.OSV, vulns.VKToPackage(p.vk)) {
					p.vulns = append(p.vulns, v.OSV)
					foundFix = true
					vkPatches[vk][i] = p
				}
			}
			if foundFix {
				continue
			}
			// No existing patch fixes this vulnerability, try find a new one.
			found, ver := findLatestMatching(ctx, cl, graph, sg, v.OSV, requiredVersions, opts)
			if !found {
				continue
			}
			// Found a patch
			newPatch := patch{
				vk:    ver,
				vulns: []*osvpb.Vulnerability{v.OSV},
			}
			// Check the vulns of other patches if this patch also fixes them.
			seenVulns := make(map[string]struct{})
			seenVulns[v.OSV.Id] = struct{}{}
			for _, p := range vkPatches[vk] {
				for _, vuln := range p.vulns {
					if _, ok := seenVulns[vuln.Id]; !ok {
						seenVulns[vuln.Id] = struct{}{}
						if !vulns.IsAffected(vuln, vulns.VKToPackage(ver)) {
							newPatch.vulns = append(newPatch.vulns, vuln)
						}
					}
				}
			}
			vkPatches[vk] = append(vkPatches[vk], newPatch)
		}
	}

	// Construct the result patches.
	var resultPatches []result.Patch
	for vk, patches := range vkPatches {
		for _, p := range patches {
			resultPatch := result.Patch{
				PackageUpdates: []result.PackageUpdate{
					result.PackageUpdate{
						Name:        vk.Name,
						VersionFrom: vk.Version,
						VersionTo:   p.vk.Version,
						Transitive:  true,
					},
				},
			}
			for _, vuln := range p.vulns {
				resultPatch.Fixed = append(resultPatch.Fixed, result.Vuln{
					ID: vuln.Id,
					Packages: []result.Package{
						result.Package{
							Name:    vk.Name,
							Version: vk.Version,
						},
					},
				})
			}
			slices.SortFunc(resultPatch.Fixed, func(a, b result.Vuln) int { return cmp.Compare(a.ID, b.ID) })
			resultPatch.Fixed = slices.CompactFunc(resultPatch.Fixed, func(a, b result.Vuln) bool { return a.ID == b.ID })
			resultPatches = append(resultPatches, resultPatch)
		}
	}

	slices.SortFunc(resultPatches, func(a, b result.Patch) int { return a.Compare(b, sys) })
	return resultPatches, nil
}

// computeAllVersionConstraints computes the overall constraints on the versions of each vulnerable package.
func computeAllVersionConstraints(vulns []resolution.Vulnerability, sys semver.System) map[resolve.VersionKey]semver.Set {
	requiredVersions := make(map[resolve.VersionKey]semver.Set)
	for _, v := range vulns {
		for _, sg := range v.Subgraphs {
			node := sg.Nodes[sg.Dependency]
			for _, p := range node.Parents {
				set, err := parseContraint(sys, p.Requirement)
				if err != nil {
					log.Warnf("failed parsing constraint %s on package %s: %v", p.Requirement, node.Version.Name, err)
					continue
				}
				if oldSet, ok := requiredVersions[node.Version]; ok {
					if err := set.Intersect(oldSet); err != nil {
						log.Warnf("failed intersecting constraints %s and %s on package %s: %v", p.Requirement, set.String(), node.Version.Name, err)
						continue
					}
				}
				requiredVersions[node.Version] = set
			}
		}
	}
	return requiredVersions
}

func parseContraint(sys semver.System, constraint string) (semver.Set, error) {
	if sys == semver.NPM && constraint == "latest" {
		// A 'latest' version is effectively meaningless in a lockfile, since what 'latest' is could have changed between locking.
		constraint = "*"
	}
	c, err := sys.ParseConstraint(constraint)
	if err != nil {
		return semver.Set{}, err
	}
	return c.Set(), nil
}

func requirementsSatisfied(reqs []resolve.RequirementVersion, graph *resolve.Graph, depEdges []resolve.Edge, sys semver.System) bool {
	for _, req := range reqs {
		if req.Type.HasAttr(dep.Dev) {
			// Dev-only dependencies are not installed.
			continue
		}
		s, err := parseContraint(sys, req.Version)
		if err != nil {
			log.Warnf("failed parsing constraint %s on package %s: %v", req.Version, req.PackageKey, err)
			return false
		}
		reqKnownAs, _ := req.Type.GetAttr(dep.KnownAs)

		idx := slices.IndexFunc(depEdges, func(e resolve.Edge) bool {
			if knownAs, _ := e.Type.GetAttr(dep.KnownAs); knownAs != reqKnownAs {
				return false
			}
			node := graph.Nodes[e.To]
			return node.Version.PackageKey == req.PackageKey
		})
		if idx == -1 {
			// No package of this version is in the graph - check if it's an optional dependency.
			if req.Type.HasAttr(dep.Opt) ||
				// Sometimes optional dependencies can also be present in the regular dependencies section.
				slices.ContainsFunc(reqs, func(r resolve.RequirementVersion) bool {
					knownAs, _ := r.Type.GetAttr(dep.KnownAs)
					return knownAs == reqKnownAs && r.PackageKey == req.PackageKey && r.Type.HasAttr(dep.Opt)
				}) {
				continue
			}
			return false
		}
		// Check if the package of this version matches the constraint.
		node := graph.Nodes[depEdges[idx].To]
		match, err := s.Match(node.Version.Version)
		if err != nil {
			log.Warnf("failed matching version %s to constraint %s on package %s: %v", node.Version.Version, s.String(), req.PackageKey, err)
			return false
		}
		if !match {
			return false
		}
	}

	return true
}

func findLatestMatching(ctx context.Context, cl resolve.Client, graph remediation.ResolvedGraph,
	sg *resolution.DependencySubgraph, v *osvpb.Vulnerability,
	requiredVersions map[resolve.VersionKey]semver.Set,
	opts *options.RemediationOptions) (bool, resolve.VersionKey) {
	vk := sg.Nodes[sg.Dependency].Version
	sys := vk.Semver()
	vers, err := cl.Versions(ctx, vk.PackageKey)
	if err != nil {
		log.Errorf("failed to get versions for package %s: %v", vk.PackageKey, err)
		return false, resolve.VersionKey{}
	}
	cmpFn := func(a, b resolve.Version) int { return sys.Compare(a.Version, b.Version) }
	if !slices.IsSortedFunc(vers, cmpFn) {
		vers = slices.Clone(vers)
		slices.SortFunc(vers, cmpFn)
	}

	var depEdges []resolve.Edge
	for _, e := range graph.Graph.Edges {
		if e.From == sg.Dependency {
			depEdges = append(depEdges, e)
		}
	}

	// Find the latest version that still satisfies the constraints
	for _, ver := range slices.Backward(vers) {
		// Check that this is allowable to upgrade to this version.
		_, diff, err := sys.Difference(vk.Version, ver.Version)
		if err != nil {
			log.Warnf("failed to compare versions %s and %s: %v", vk.Version, ver.Version, err)
			continue
		}
		if !opts.UpgradeConfig.Get(vk.Name).Allows(diff) {
			continue
		}

		// Check that this version is not vulnerable.
		if vulns.IsAffected(v, vulns.VKToPackage(ver.VersionKey)) {
			continue
		}

		// Check that this version satisfies the constraints of all dependent packages.
		if s, ok := requiredVersions[vk]; ok {
			match, err := s.Match(ver.Version)
			if err != nil {
				log.Warnf("failed matching version %s to constraints %s on package %s: %v", ver.Version, s.String(), vk.Name, err)
				continue
			}
			if !match {
				continue
			}
		}

		// Check that all of this version's dependencies are satisfied by the existing graph.
		reqs, err := cl.Requirements(ctx, ver.VersionKey)
		if err != nil {
			log.Warnf("failed to get requirements for package %s: %v", ver.VersionKey, err)
			continue
		}
		if !requirementsSatisfied(reqs, graph.Graph, depEdges, sys) {
			continue
		}

		// Found a patch
		return true, ver.VersionKey
	}

	return false, resolve.VersionKey{}
}
