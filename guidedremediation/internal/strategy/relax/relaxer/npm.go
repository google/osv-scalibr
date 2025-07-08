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

package relaxer

import (
	"context"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scalibr/log"
)

// NpmRelaxer implements RequirementRelaxer for npm.
type NpmRelaxer struct{}

// Relax attempts to relax import requirement.
// Returns the newly relaxed import and true it was successful.
// If unsuccessful, it returns the original import and false.
func (r NpmRelaxer) Relax(ctx context.Context, cl resolve.Client, req resolve.RequirementVersion, config upgrade.Config) (resolve.RequirementVersion, bool) {
	configLevel := config.Get(req.Name)
	if configLevel == upgrade.None {
		return req, false
	}

	c, err := semver.NPM.ParseConstraint(req.Version)
	if err != nil {
		// The specified version is not a valid semver constraint
		// Check if it's a version tag (usually 'latest') by seeing if there are matching versions
		vks, err := cl.MatchingVersions(ctx, req.VersionKey)
		if err != nil || len(vks) == 0 { // no matches, cannot relax
			return req, false
		}
		// Use the first matching version (there should only be one) as a pinned version
		c, err = semver.NPM.ParseConstraint(vks[0].Version)
		if err != nil {
			return req, false
		}
	}

	// Get all the concrete versions of the package
	allVKs, err := cl.Versions(ctx, req.PackageKey)
	if err != nil {
		return req, false
	}
	var vers []*semver.Version
	for _, vk := range allVKs {
		if vk.VersionType != resolve.Concrete {
			continue
		}
		sv, err := semver.NPM.Parse(vk.Version)
		if err != nil {
			log.Warnf("failed to parse npm version %s: %v", vk.Version, err)
			continue
		}
		vers = append(vers, sv)
	}
	slices.SortFunc(vers, func(a *semver.Version, b *semver.Version) int {
		return a.Compare(b)
	})

	// Find the versions on either side of the upper boundary of the requirement
	var lastIdx int   // highest version matching constraint
	nextIdx := -1     // next version outside of range, preferring non-prerelease
	nextIsPre := true // if the next version is a prerelease version
	for lastIdx = len(vers) - 1; lastIdx >= 0; lastIdx-- {
		v := vers[lastIdx]
		if c.MatchVersion(v) { // found the upper bound, stop iterating
			break
		}

		// Want to prefer non-prerelease versions, so only select one if we haven't seen any non-prerelease versions
		if !v.IsPrerelease() || nextIsPre {
			nextIdx = lastIdx
			nextIsPre = v.IsPrerelease()
		}
	}

	// Didn't find any higher versions of the package
	if nextIdx == -1 {
		return req, false
	}

	// No versions match the existing constraint, something is wrong
	if lastIdx == -1 {
		return req, false
	}

	// Our desired relaxation ordering is
	// 1.2.3 -> 1.2.* -> 1.*.* -> 2.*.* -> 3.*.* -> ...
	// But we want to use npm-like version specifiers e.g.
	// 1.2.3 -> ~1.2.4 -> ^1.4.5 -> ^2.6.7 -> ^3.8.9 -> ...
	// using the latest versions of the ranges

	cmpVer := vers[lastIdx]
	_, diff := cmpVer.Difference(vers[nextIdx])
	if !configLevel.Allows(diff) {
		return req, false
	}
	if diff == semver.DiffMajor {
		// Want to step only one major version at a time
		// Instead of looking for a difference larger than major,
		// we want to look for a major version bump from the first next version
		cmpVer = vers[nextIdx]
		diff = semver.DiffMinor
	}

	// Find the highest version with the same difference
	best := vers[nextIdx]
	for i := nextIdx + 1; i < len(vers); i++ {
		_, d := cmpVer.Difference(vers[i])
		// If we've exceeded our allowed upgrade level, stop looking.
		if !configLevel.Allows(d) {
			break
		}

		// DiffMajor < DiffMinor < DiffPatch < DiffPrerelease
		// So if d is less than the original diff, it represents a larger change
		if d < diff {
			break
		}
		if !vers[i].IsPrerelease() || nextIsPre {
			best = vers[i]
		}
	}

	if diff == semver.DiffPatch {
		req.Version = "~" + best.String()
	} else {
		req.Version = "^" + best.String()
	}

	return req, true
}
