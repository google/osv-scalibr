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

// Package relax implements the relax remediation strategy.
package relax

import (
	"context"
	"fmt"
	"slices"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/common"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/relax/relaxer"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

// ComputePatches attempts to resolve each vulnerability found in result independently,
// returning the list of unique possible patches.
// Vulnerabilities are resolved by relaxing version constraints of the direct dependencies that bring in the vulnerable packages.
// If a patch introduces new vulnerabilities, additional relaxations are attempted for the new vulnerabilities.
func ComputePatches(ctx context.Context, cl resolve.Client, ve enricher.Enricher, resolved *remediation.ResolvedManifest, opts *options.RemediationOptions) (common.PatchResult, error) {
	patchFn := func(vulnIDs []string) common.StrategyResult {
		patched, err := patchVulns(ctx, cl, ve, resolved, vulnIDs, opts)
		return common.StrategyResult{
			VulnIDs:  vulnIDs,
			Resolved: patched,
			Err:      err}
	}

	return common.ComputePatches(patchFn, resolved, false)
}

// patchVulns tries to fix all vulns in vulnIDs by relaxing direct dependency versions.
// returns ErrPatchImpossible if all cannot be patched.
func patchVulns(ctx context.Context, cl resolve.Client, ve enricher.Enricher, resolved *remediation.ResolvedManifest, vulnIDs []string, opts *options.RemediationOptions) (*remediation.ResolvedManifest, error) {
	resolved = &remediation.ResolvedManifest{
		Manifest:      resolved.Manifest.Clone(),
		ResolvedGraph: resolved.ResolvedGraph,
	}

	reqRelaxer, err := relaxer.ForEcosystem(resolved.Manifest.System())
	if err != nil {
		return nil, err
	}
	toRelax := reqsToRelax(ctx, cl, resolved, vulnIDs, opts)
	for len(toRelax) > 0 {
		for _, req := range toRelax {
			if opts.UpgradeConfig.Get(req.Name) == upgrade.None {
				return nil, common.ErrPatchImpossible
			}
			newVer, ok := reqRelaxer.Relax(ctx, cl, req, opts.UpgradeConfig)
			if !ok {
				return nil, common.ErrPatchImpossible
			}
			if err := resolved.Manifest.PatchRequirement(newVer); err != nil {
				return nil, fmt.Errorf("failed to patch requirement %v: %w", newVer, err)
			}
		}

		// re-resolve the relaxed manifest
		var err error
		resolved.Graph, err = resolution.Resolve(ctx, cl, resolved.Manifest, opts.ResolutionOptions)
		if err != nil {
			return nil, err
		}
		resolved.UnfilteredVulns, err = resolution.FindVulnerabilities(ctx, ve, resolved.Manifest.Groups(), resolved.Graph)
		if err != nil {
			return nil, err
		}
		resolved.Vulns = slices.Clone(resolved.UnfilteredVulns)
		resolved.Vulns = slices.DeleteFunc(resolved.Vulns, func(v resolution.Vulnerability) bool { return !remediation.MatchVuln(*opts, v) })
		toRelax = reqsToRelax(ctx, cl, resolved, vulnIDs, opts)
	}

	return resolved, nil
}

func reqsToRelax(ctx context.Context, cl resolve.Client, resolved *remediation.ResolvedManifest, vulnIDs []string, opts *options.RemediationOptions) []resolve.RequirementVersion {
	var toRelax []resolve.RequirementVersion
	for _, v := range resolved.Vulns {
		if !slices.Contains(vulnIDs, v.OSV.Id) {
			continue
		}
		// Only relax dependencies if their distance is less than MaxDepth
		for _, sg := range v.Subgraphs {
			constr := sg.ConstrainingSubgraph(ctx, cl, v.OSV)
			for _, edge := range constr.Nodes[0].Children {
				gNode := constr.Nodes[edge.To]
				if opts.MaxDepth > 0 && gNode.Distance+1 > opts.MaxDepth {
					continue
				}
				toRelax = append(toRelax, resolve.RequirementVersion{
					VersionKey: resolve.VersionKey{
						PackageKey:  gNode.Version.PackageKey,
						Version:     edge.Requirement,
						VersionType: resolve.Requirement,
					},
					Type: edge.Type.Clone(),
				})
			}
		}
	}

	cmpFn := func(a, b resolve.RequirementVersion) int {
		if cmp := a.Compare(b.VersionKey); cmp != 0 {
			return cmp
		}
		return a.Type.Compare(b.Type)
	}
	slices.SortFunc(toRelax, cmpFn)
	toRelax = slices.CompactFunc(toRelax, func(a, b resolve.RequirementVersion) bool { return cmpFn(a, b) == 0 })

	return toRelax
}
