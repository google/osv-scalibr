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

package suggest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	mavenmanifest "github.com/google/osv-scalibr/guidedremediation/internal/manifest/maven"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scalibr/internal/mavenutil"
	"golang.org/x/exp/slices"
)

// MavenSuggester suggests update patch for Maven dependencies.
type MavenSuggester struct{}

// Suggest returns the Patch to update Maven dependencies to a newer
// version based on the options.
func (ms *MavenSuggester) Suggest(ctx context.Context, mf manifest.Manifest, opts options.UpdateOptions) (result.Patch, error) {
	specific, ok := mf.EcosystemSpecific().(mavenmanifest.ManifestSpecific)
	if !ok {
		return result.Patch{}, errors.New("invalid Maven ManifestSpecific data")
	}

	var packageUpdates []result.PackageUpdate
	for _, req := range append(mf.Requirements(), specific.RequirementsForUpdates...) {
		if opts.UpgradeConfig.Get(req.Name) == upgrade.None {
			continue
		}
		if opts.IgnoreDev && slices.Contains(mf.Groups()[mavenmanifest.MakeRequirementKey(req)], "test") {
			// Skip the update if the dependency is of development group
			// and updates on development dependencies are not desired
			continue
		}
		if strings.Contains(req.Name, "${") && strings.Contains(req.Version, "${") {
			// If there are unresolved properties, we should skip this version.
			continue
		}

		latest, err := suggestMavenVersion(ctx, opts.ResolveClient, req, opts.UpgradeConfig.Get(req.Name))
		if err != nil {
			return result.Patch{}, fmt.Errorf("suggesting latest version of %s: %w", req.Version, err)
		}
		if latest.Version == req.Version {
			// No need to update
			continue
		}

		pu := result.PackageUpdate{
			Name:        req.Name,
			VersionFrom: req.Version,
			VersionTo:   latest.Version,
			Type:        req.Type,
		}
		origDep := mavenmanifest.OriginalDependency(pu, specific.OriginalRequirements)
		if origDep.Name() != ":" {
			// An empty name indicates the dependency is not found, so the original dependency is not in the base project.
			// Only add a package update if it is from the base project.
			packageUpdates = append(packageUpdates, pu)
		}
	}

	return result.Patch{PackageUpdates: packageUpdates}, nil
}

// suggestMavenVersion returns the latest version based on the given Maven requirement version.
// If there is no newer version available, req will be returned.
// For a version range requirement,
//   - the greatest version matching the constraint is assumed when deciding whether the
//     update is a major update or not.
//   - if the latest version does not satisfy the constraint, this version is returned;
//     otherwise, the original version range requirement is returned.
func suggestMavenVersion(ctx context.Context, cl resolve.Client, req resolve.RequirementVersion, level upgrade.Level) (resolve.RequirementVersion, error) {
	versions, err := cl.Versions(ctx, req.PackageKey)
	if err != nil {
		return resolve.RequirementVersion{}, fmt.Errorf("requesting versions of Maven package %s: %w", req.Name, err)
	}
	semvers := make([]*semver.Version, 0, len(versions))
	for _, ver := range versions {
		parsed, err := semver.Maven.Parse(ver.Version)
		if err != nil {
			log.Printf("parsing Maven version %s: %v", parsed, err)
			continue
		}
		semvers = append(semvers, parsed)
	}

	constraint, err := semver.Maven.ParseConstraint(req.Version)
	if err != nil {
		return resolve.RequirementVersion{}, fmt.Errorf("parsing Maven constraint %s: %w", req.Version, err)
	}

	var current *semver.Version
	if constraint.IsSimple() {
		// Constraint is a simple version string, so can be parsed to a single version.
		current, err = semver.Maven.Parse(req.Version)
		if err != nil {
			return resolve.RequirementVersion{}, fmt.Errorf("parsing Maven version %s: %w", req.Version, err)
		}
	} else {
		// Guess the latest version satisfying the constraint is being used
		for _, v := range semvers {
			if constraint.MatchVersion(v) && current.Compare(v) < 0 {
				current = v
			}
		}
	}

	var newReq *semver.Version
	for _, v := range semvers {
		if mavenutil.CompareVersions(req.VersionKey, v, newReq) < 0 {
			// Skip versions smaller than the current requirement
			continue
		}
		if _, diff := v.Difference(current); !level.Allows(diff) {
			continue
		}
		newReq = v
	}
	if constraint.IsSimple() || !constraint.MatchVersion(newReq) {
		// For version range requirement, update the requirement if the
		// new requirement does not satisfy the constraint.
		req.Version = newReq.String()
	}

	return req, nil
}
