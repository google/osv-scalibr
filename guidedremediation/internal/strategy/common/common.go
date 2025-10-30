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

// Package common implements functions common to multiple remediation strategies.
package common

import (
	"errors"
	"slices"

	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/log"
)

// PatchFunc is a bound function that attempts to patch the given vulns.
type PatchFunc func([]string) StrategyResult

// StrategyResult is the result of a remediation strategy.
type StrategyResult struct {
	VulnIDs  []string
	Resolved *remediation.ResolvedManifest
	Err      error
}

// ErrPatchImpossible is returned when no patch is possible for the vulns.
var ErrPatchImpossible = errors.New("cannot find a patch for the vulns")

// PatchResult is the result of computing patches.
type PatchResult struct {
	Patches  []result.Patch                  // the list of unique patches
	Resolved []*remediation.ResolvedManifest // the resolved manifest after each patch is applied
}

// ComputePatches attempts to resolve each vulnerability found in the resolved manifest independently,
// returning the list of unique possible patches.
// Vulnerabilities are resolved by calling patchFunc for each vulnerability.
// If a patch introduces new vulnerabilities, additional patches are attempted for the new vulnerabilities.
// If groupIntroduced is true, introduced vulns are all attempted to be patched together.
// Otherwise, they are patched one-by-one independently.
func ComputePatches(patchFunc PatchFunc, resolved *remediation.ResolvedManifest, groupIntroduced bool) (PatchResult, error) {
	ch := make(chan StrategyResult)
	doPatch := func(vulnIDs []string) {
		ch <- patchFunc(vulnIDs)
	}

	toProcess := 0
	for _, v := range resolved.Vulns {
		go doPatch([]string{v.OSV.Id})
		toProcess++
	}

	type patchRes struct {
		patch    result.Patch
		resolved *remediation.ResolvedManifest
	}

	var allResults []patchRes
	for toProcess > 0 {
		r := <-ch
		toProcess--
		if r.Err != nil {
			if !errors.Is(r.Err, ErrPatchImpossible) {
				log.Warnf("error attempting to patch for vulns %v: %v", r.VulnIDs, r.Err)
			}
			continue
		}

		patch := remediation.ConstructPatches(resolved, r.Resolved)
		if len(patch.PackageUpdates) == 0 {
			continue
		}
		allResults = append(allResults, patchRes{patch: patch, resolved: r.Resolved})

		// If there are any new vulns, try patching them as well
		var newlyAdded []string
		for _, v := range patch.Introduced {
			if !slices.Contains(r.VulnIDs, v.ID) {
				newlyAdded = append(newlyAdded, v.ID)
			}
		}
		if len(newlyAdded) > 0 {
			if groupIntroduced {
				// If we group introduced vulns, try patch them all together.
				go doPatch(append(r.VulnIDs, newlyAdded...)) // No need to clone r.VulnIDs here
				toProcess++
			} else {
				// If we don't group introduced vulns, try patch individually.
				// This can cause every permutation of introduced vulns to be computed.
				for _, v := range newlyAdded {
					go doPatch(append(slices.Clone(r.VulnIDs), v))
					toProcess++
				}
			}
		}
	}

	// Sort and remove duplicate patches
	cmpFn := func(a, b patchRes) int { return a.patch.Compare(b.patch, resolved.Manifest.System().Semver()) }
	slices.SortFunc(allResults, cmpFn)
	allResults = slices.CompactFunc(allResults, func(a, b patchRes) bool { return cmpFn(a, b) == 0 })

	var output PatchResult
	output.Patches = make([]result.Patch, 0, len(allResults))
	output.Resolved = make([]*remediation.ResolvedManifest, 0, len(allResults))
	for _, r := range allResults {
		output.Patches = append(output.Patches, r.patch)
		output.Resolved = append(output.Resolved, r.resolved)
	}

	return output, nil
}
