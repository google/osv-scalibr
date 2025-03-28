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

// Package override implements the override remediation strategy.
package override

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/vulns"
	"github.com/google/osv-scalibr/guidedremediation/matcher"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scalibr/internal/mavenutil"
	"github.com/google/osv-scalibr/log"
)

// ComputePatches attempts to resolve each vulnerability found in result independently, returning the list of unique possible patches.
// Vulnerabilities are resolved by directly overriding versions of vulnerable packages to non-vulnerable versions.
// If a patch introduces new vulnerabilities, additional overrides are attempted for the new vulnerabilities.
func ComputePatches(ctx context.Context, cl resolve.Client, vm matcher.VulnerabilityMatcher, resolved *remediation.ResolvedManifest, opts *options.RemediationOptions) ([]result.Patch, error) {
	// Do the remediation attempts concurrently
	type overrideResult struct {
		vulnIDs  []string
		resolved *remediation.ResolvedManifest
		err      error
	}
	ch := make(chan overrideResult)
	doOverride := func(vulnIDs []string) {
		resolved, err := patchVulns(ctx, cl, vm, resolved, vulnIDs, opts)
		ch <- overrideResult{vulnIDs, resolved, err}
	}

	toProcess := 0
	for _, v := range resolved.Vulns {
		go doOverride([]string{v.OSV.ID})
		toProcess++
	}

	var allResults []result.Patch
	for toProcess > 0 {
		r := <-ch
		toProcess--
		if r.err != nil {
			if !errors.Is(r.err, errOverrideImpossible) {
				log.Warnf("error attempting to compute override patch for vulns %v: %v", r.vulnIDs, r.err)
			}
			continue
		}

		patch := remediation.ConstructPatches(resolved, r.resolved)
		if len(patch.PackageUpdates) == 0 {
			continue
		}
		allResults = append(allResults, patch)

		// If there are any new vulns, try override them as well
		var newlyAdded []string
		for _, v := range patch.Introduced {
			if !slices.Contains(r.vulnIDs, v.ID) {
				newlyAdded = append(newlyAdded, v.ID)
			}
		}
		if len(newlyAdded) > 0 {
			go doOverride(append(r.vulnIDs, newlyAdded...)) // No need to clone r.VulnIDs here
			toProcess++
		}
	}

	// Sort and remove duplicate patches
	cmpFn := func(a, b result.Patch) int { return a.Compare(b, resolved.Manifest.System().Semver()) }
	slices.SortFunc(allResults, cmpFn)
	allResults = slices.CompactFunc(allResults, func(a, b result.Patch) bool { return cmpFn(a, b) == 0 })

	return allResults, nil
}

var errOverrideImpossible = errors.New("cannot fix vulns by overrides")

// patchVulns tries to fix as many vulns in vulnIDs as possible by overriding dependency versions.
// returns errOverrideImpossible if 0 vulns are patchable, otherwise returns the most possible patches.
func patchVulns(ctx context.Context, cl resolve.Client, vm matcher.VulnerabilityMatcher, resolved *remediation.ResolvedManifest, vulnIDs []string, opts *options.RemediationOptions) (*remediation.ResolvedManifest, error) {
	resolved = &remediation.ResolvedManifest{
		Manifest:        resolved.Manifest.Clone(),
		Graph:           resolved.Graph,
		Vulns:           resolved.Vulns,
		UnfilteredVulns: resolved.UnfilteredVulns,
	}

	for {
		// Find the relevant vulns affecting each version key.
		vkVulns := make(map[resolve.VersionKey][]*resolution.Vulnerability)
		for i, v := range resolved.Vulns {
			if !slices.Contains(vulnIDs, v.OSV.ID) {
				continue
			}
			// Keep track of VersionKeys we've seen for this vuln to avoid duplicates.
			// Usually, there will only be one VersionKey per vuln, but some vulns affect multiple packages.
			seenVKs := make(map[resolve.VersionKey]struct{})
			// Use the Subgraphs to find all the affected nodes.
			for _, sg := range v.Subgraphs {
				for _, e := range sg.Nodes[sg.Dependency].Parents {
					// It's hard to know if a specific classifier or type exists for a given version.
					// Blindly updating versions can lead to compilation failures if the artifact+version+classifier+type doesn't exist.
					// We can't reliably attempt remediation in these cases, so don't try.
					if e.Type.HasAttr(dep.MavenClassifier) || e.Type.HasAttr(dep.MavenArtifactType) {
						return nil, fmt.Errorf("%w: cannot fix vulns in artifacts with classifier or type", errOverrideImpossible)
					}
					vk := sg.Nodes[sg.Dependency].Version
					if _, seen := seenVKs[vk]; !seen {
						vkVulns[vk] = append(vkVulns[vk], &resolved.Vulns[i])
						seenVKs[vk] = struct{}{}
					}
				}
			}
		}

		if len(vkVulns) == 0 {
			// All vulns have been fixed.
			break
		}

		didPatch := false

		// For each VersionKey, try fix as many of the vulns affecting it as possible.
		for vk, vulnerabilities := range vkVulns {
			// Consider vulns affecting packages we don't want to change unfixable
			if opts.UpgradeConfig.Get(vk.Name) == upgrade.None {
				continue
			}

			bestVK := vk
			bestCount := len(vulnerabilities) // remaining vulns
			versions, err := getVersionsGreater(ctx, cl, vk)
			if err != nil {
				return nil, err
			}

			// Find the minimal greater version that fixes as many vulnerabilities as possible.
			for _, ver := range versions {
				// Break if we've encountered a disallowed version update.
				if _, diff, _ := vk.System.Semver().Difference(vk.Version, ver.Version); !opts.UpgradeConfig.Get(vk.Name).Allows(diff) {
					break
				}

				// Count the remaining known vulns that affect this version.
				count := 0 // remaining vulns
				for _, rv := range vulnerabilities {
					if vulns.IsAffected(rv.OSV, vulns.VKToPackage(ver.VersionKey)) {
						count++
					}
				}
				if count < bestCount {
					// Found a new candidate.
					bestCount = count
					bestVK = ver.VersionKey
					if bestCount == 0 { // stop if there are 0 vulns remaining
						break
					}
				}
			}

			if bestCount < len(vulnerabilities) {
				// Found a version that fixes some vulns.
				if err := resolved.Manifest.PatchRequirement(resolve.RequirementVersion{VersionKey: bestVK}); err != nil {
					return nil, err
				}
				didPatch = true
			}
		}

		if !didPatch {
			break
		}

		// Re-resolve the manifest
		var err error
		resolved.Graph, err = resolution.Resolve(ctx, cl, resolved.Manifest, opts.ResolutionOptions)
		if err != nil {
			return nil, err
		}
		resolved.UnfilteredVulns, err = resolution.FindVulnerabilities(ctx, vm, resolved.Manifest, resolved.Graph)
		if err != nil {
			return nil, err
		}
		resolved.Vulns = slices.Clone(resolved.UnfilteredVulns)
		resolved.Vulns = slices.DeleteFunc(resolved.Vulns, func(v resolution.Vulnerability) bool { return !remediation.MatchVuln(*opts, v) })
	}

	return resolved, nil
}

// getVersionsGreater gets the known versions of a package that are greater than the given version, sorted in ascending order.
func getVersionsGreater(ctx context.Context, cl resolve.Client, vk resolve.VersionKey) ([]resolve.Version, error) {
	// Get & sort all the valid versions of this package
	versions, err := cl.Versions(ctx, vk.PackageKey)
	if err != nil {
		return nil, err
	}
	semvers := make(map[resolve.VersionKey]*semver.Version)
	sv := vk.System.Semver()
	for _, ver := range versions {
		parsed, err := sv.Parse(ver.Version)
		if err != nil {
			log.Warnf("error parsing version %s: %v", parsed, err)
			continue
		}
		semvers[ver.VersionKey] = parsed
	}

	cmpFunc := func(a, b resolve.Version) int {
		if vk.System == resolve.Maven {
			return mavenutil.CompareVersions(vk, semvers[a.VersionKey], semvers[b.VersionKey])
		}

		return sv.Compare(a.Version, b.Version)
	}
	if !slices.IsSortedFunc(versions, cmpFunc) {
		versions = slices.Clone(versions)
		slices.SortFunc(versions, cmpFunc)
	}
	// Find the index of the next higher version
	offset, vkFound := slices.BinarySearchFunc(versions, resolve.Version{VersionKey: vk}, cmpFunc)
	if vkFound { // if the given version somehow doesn't exist, offset will already be at the next higher version
		offset++
	}

	return versions[offset:], nil
}
