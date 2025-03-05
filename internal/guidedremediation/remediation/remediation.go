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
	"math"
	"slices"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest"
	"github.com/google/osv-scalibr/internal/guidedremediation/matcher"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation/upgrade"
	"github.com/google/osv-scalibr/internal/guidedremediation/resolution"
	"github.com/google/osv-scalibr/internal/guidedremediation/severity"
	"github.com/google/osv-scalibr/internal/guidedremediation/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Options is the configuration for remediation.
type Options struct {
	resolution.ResolveOptions
	IgnoreVulns   []string // Vulnerability IDs to ignore
	ExplicitVulns []string // If set, only consider these vulnerability IDs & ignore all others

	DevDeps     bool    // Whether to consider vulnerabilities in dev dependencies
	MinSeverity float64 // Minimum vulnerability CVSS score to consider
	MaxDepth    int     // Maximum depth of dependency to consider vulnerabilities for (e.g. 1 for direct only)

	UpgradeConfig upgrade.Config // Allowed upgrade levels per package.
}

// DefaultOptions creates a default initialized remediation configuration.
func DefaultOptions() *Options {
	return &Options{
		DevDeps:       true,
		MaxDepth:      -1,
		UpgradeConfig: upgrade.NewConfig(),
	}
}

// MatchVuln checks whether a found vulnerability should be considered according to the remediation options.
func (opts *Options) MatchVuln(v resolution.Vulnerability) bool {
	if opts.matchID(v, opts.IgnoreVulns) {
		return false
	}

	if !opts.DevDeps && v.DevOnly {
		return false
	}

	return opts.matchSeverity(v) && opts.matchDepth(v)
}

func (opts *Options) matchID(v resolution.Vulnerability, ids []string) bool {
	if slices.Contains(ids, v.OSV.ID) {
		return true
	}

	for _, id := range v.OSV.Aliases {
		if slices.Contains(ids, id) {
			return true
		}
	}

	return false
}

func (opts *Options) matchSeverity(v resolution.Vulnerability) bool {
	maxScore := -1.0
	severities := v.OSV.Severity
	if len(severities) == 0 {
		// There are no top-level severity, see if there are individual affected[].severity field.
		severities = []osvschema.Severity{}
		for _, sg := range v.Subgraphs {
			inv := vulns.VKToInventory(sg.Nodes[sg.Dependency].Version)
			// Make and match a dummy OSV record per affected[] entry to determine which applies.
			for _, affected := range v.OSV.Affected {
				if vulns.IsAffected(&osvschema.Vulnerability{Affected: []osvschema.Affected{affected}}, inv) {
					severities = append(severities, affected.Severity...)

					break
				}
			}
		}
	}

	for _, sev := range severities {
		if score, err := severity.CalculateScore(sev); err == nil { // skip errors
			maxScore = max(maxScore, score)
		}
	}

	// CVSS scores are meant to only be to 1 decimal place
	// and we want to avoid something being falsely rejected/included due to floating point precision.
	// Multiply and round to only consider relevant parts of the score.
	return math.Round(10*maxScore) >= math.Round(10*opts.MinSeverity) ||
		maxScore < 0 // Always include vulns with unknown severities
}

func (opts *Options) matchDepth(v resolution.Vulnerability) bool {
	if opts.MaxDepth <= 0 {
		return true
	}

	for _, sg := range v.Subgraphs {
		if sg.Nodes[0].Distance <= opts.MaxDepth {
			return true
		}
	}

	return false
}

// ResolvedManifest is a manifest, its resolved dependency graph, and the vulnerabilities found in it.
type ResolvedManifest struct {
	Manifest        manifest.Manifest
	Graph           *resolve.Graph
	Vulns           []resolution.Vulnerability
	UnfilteredVulns []resolution.Vulnerability
}

// ResolveManifest resolves and find vulnerabilities in a manifest.
func ResolveManifest(ctx context.Context, cl resolve.Client, vm matcher.VulnerabilityMatcher, m manifest.Manifest, opts *Options) (*ResolvedManifest, error) {
	g, err := resolution.Resolve(ctx, cl, m, opts.ResolveOptions)
	if err != nil {
		return nil, err
	}

	allVulns, err := resolution.FindVulnerabilities(ctx, vm, m, g)
	if err != nil {
		return nil, err
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
	filteredVulns = slices.DeleteFunc(filteredVulns, func(v resolution.Vulnerability) bool { return !opts.MatchVuln(v) })

	return &ResolvedManifest{
		Manifest:        m,
		Graph:           g,
		Vulns:           filteredVulns,
		UnfilteredVulns: allVulns,
	}, nil
}

// ConstructPatches computes the effective Patches that were applied to oldRes to get newRes.
func ConstructPatches(oldRes, newRes *ResolvedManifest) Patch {
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

	var output Patch
	output.Fixed = make([]Vuln, 0, len(fixedVulns))
	for _, v := range fixedVulns {
		vuln := Vuln{ID: v.OSV.ID}
		for _, sg := range v.Subgraphs {
			n := oldRes.Graph.Nodes[sg.Dependency]
			vuln.Packages = append(vuln.Packages, Package{Name: n.Version.Name, Version: n.Version.Version})
		}
		output.Fixed = append(output.Fixed, vuln)
	}
	slices.SortFunc(output.Fixed, func(a, b Vuln) int { return cmp.Compare(a.ID, b.ID) })

	if len(introducedVulns) > 0 {
		output.Introduced = make([]Vuln, 0, len(introducedVulns))
	}
	for _, v := range introducedVulns {
		vuln := Vuln{ID: v.OSV.ID}
		for _, sg := range v.Subgraphs {
			n := newRes.Graph.Nodes[sg.Dependency]
			vuln.Packages = append(vuln.Packages, Package{Name: n.Version.Name, Version: n.Version.Version})
		}
		output.Introduced = append(output.Introduced, vuln)
	}
	slices.SortFunc(output.Introduced, func(a, b Vuln) int { return cmp.Compare(a.ID, b.ID) })

	oldReqs := make(map[resolve.PackageKey]resolve.RequirementVersion)
	for _, req := range oldRes.Manifest.Requirements() {
		oldReqs[req.PackageKey] = req
	}
	for _, req := range newRes.Manifest.Requirements() {
		oldReq, ok := oldReqs[req.PackageKey]
		if !ok {
			output.PackageUpdates = append(output.PackageUpdates, PackageUpdate{
				Name:        req.Name,
				VersionFrom: "",
				VersionTo:   req.Version,
			})

			continue
		}
		if req.Version == oldReq.Version {
			continue
		}

		output.PackageUpdates = append(output.PackageUpdates, PackageUpdate{
			Name:        req.Name,
			VersionFrom: oldReq.Version,
			VersionTo:   req.Version,
		})
	}
	slices.SortFunc(output.PackageUpdates, func(a, b PackageUpdate) int {
		return cmp.Compare(a.Name, b.Name)
	})
	// It's possible something is in the requirements twice (e.g. with Maven dependencyManagement)
	// Deduplicate the patches in this case.
	output.PackageUpdates = slices.Compact(output.PackageUpdates)

	return output
}
