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

package suggest

import (
	"context"
	"fmt"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scalibr/log"
)

// PythonSuggester suggests update patch for Python dependencies.
type PythonSuggester struct{}

// Suggest returns the Patch to update Python dependencies to a newer
// version based on the options.
func (ps *PythonSuggester) Suggest(ctx context.Context, mf manifest.Manifest, opts options.UpdateOptions) (result.Patch, error) {
	var packageUpdates []result.PackageUpdate
	updated := make(map[resolve.VersionKey]bool)
	for _, req := range mf.Requirements() {
		if opts.UpgradeConfig.Get(req.Name) == upgrade.None {
			continue
		}
		if opts.IgnoreDev && slices.Contains(mf.Groups()[manifest.RequirementKey(req.PackageKey)], "dev") {
			// Skip the update if the dependency is of development group
			// and updates on development dependencies are not desired
			continue
		}
		if updated[req.VersionKey] {
			// Skip the update if the dependency is already updated.
			continue
		}
		updated[req.VersionKey] = true

		latest, err := suggestPythonVersion(ctx, opts.ResolveClient, req, opts.UpgradeConfig.Get(req.Name))
		if err != nil {
			log.Warnf("failed to suggest Python version for package %q: %v", req.Name, err)
			continue
		}
		if latest.Version == req.Version {
			// No need to update
			continue
		}

		packageUpdates = append(packageUpdates, result.PackageUpdate{
			Name:        req.Name,
			VersionFrom: req.Version,
			VersionTo:   latest.Version,
			Type:        req.Type,
		})
	}

	return result.Patch{PackageUpdates: packageUpdates}, nil
}

// suggestPythonVersion returns the latest version based on the given Python requirement version.
// If there is no newer version available, req will be returned.
func suggestPythonVersion(ctx context.Context, cl resolve.Client, req resolve.RequirementVersion, level upgrade.Level) (resolve.RequirementVersion, error) {
	versions, err := cl.Versions(ctx, req.PackageKey)
	if err != nil {
		return resolve.RequirementVersion{}, fmt.Errorf("requesting versions of Python package %s: %w", req.Name, err)
	}
	if len(versions) == 0 {
		return resolve.RequirementVersion{}, fmt.Errorf("no versions found for Python package %s", req.Name)
	}

	semvers := make([]*semver.Version, 0, len(versions))
	for _, ver := range versions {
		parsed, err := semver.PyPI.Parse(ver.Version)
		if err != nil {
			log.Warnf("parsing Python version %q: %v", ver.Version, err)
			continue
		}
		semvers = append(semvers, parsed)
	}
	if len(semvers) == 0 {
		// Not able to parse any versions, so return the original requirement.
		return req, nil
	}

	constraint, err := semver.PyPI.ParseConstraint(req.Version)
	if err != nil {
		return resolve.RequirementVersion{}, fmt.Errorf("parsing Python constraint %s: %w", req.Version, err)
	}

	// Guess the latest version satisfying the constraint is being used
	var current *semver.Version
	for _, v := range semvers {
		if constraint.MatchVersion(v) && (current == nil || current.Compare(v) < 0) {
			current = v
		}
	}
	if current == nil {
		// Not able to guess the current concrete version, so return the original requirement.
		return req, nil
	}

	var newReq *semver.Version
	for _, v := range semvers {
		if v.Compare(current) < 0 {
			// Skip versions smaller than the current requirement
			continue
		}
		if newReq != nil && v.Compare(newReq) <= 0 {
			// Skip versions smaller than the current best version
			continue
		}
		if _, diff := v.Difference(current); !level.Allows(diff) {
			continue
		}
		if v.IsPrerelease() {
			// Skip prerelease versions for updates considering that most people prefer stable, released
			// versions for dependency updates.
			continue
		}
		newReq = v
	}
	if newReq != nil && newReq.Compare(current) > 0 {
		// Update the requirement if a newer version is found.
		req.Version = "==" + newReq.String()
	}

	return req, nil
}
