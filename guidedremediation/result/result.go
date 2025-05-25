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

// Package result defines the remediation result structs
package result

import (
	"cmp"

	"deps.dev/util/resolve/dep"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Result is a description of changes made by guided remediation to a manifest/lockfile.
type Result struct {
	Path            string              `json:"path"`             // path to the manifest/lockfile.
	Ecosystem       osvschema.Ecosystem `json:"ecosystem"`        // the OSV ecosystem of the file (npm, Maven)
	Strategy        strategy.Strategy   `json:"strategy"`         // the remediation strategy that was used.
	Vulnerabilities []Vuln              `json:"vulnerabilities"`  // vulns detected in the initial manifest/lockfile.
	Patches         []Patch             `json:"patches"`          // list of dependency patches that were applied.
	Errors          []ResolveError      `json:"errors,omitempty"` // non-fatal errors encountered in initial resolution.
}

// Vuln represents a vulnerability that was found in a project.
type Vuln struct {
	ID           string    `json:"id"`                     // the OSV ID of the vulnerability.
	Packages     []Package `json:"packages"`               // the list of packages in the dependency graph this vuln affects.
	Unactionable bool      `json:"unactionable,omitempty"` // true if no fix patch available, or if constraints would prevent one.
}

// Patch represents an isolated patch to one or more dependencies that fixes one or more vulns.
type Patch struct {
	PackageUpdates []PackageUpdate `json:"packageUpdates"`       // dependencies that were updated.
	Fixed          []Vuln          `json:"fixed,omitempty"`      // vulns fixed by this patch.
	Introduced     []Vuln          `json:"introduced,omitempty"` // vulns introduced by this patch.
}

// Compare compares Patches based on 'effectiveness' (best first):
//
// Sort order:
//  1. (number of fixed vulns - introduced vulns) / (number of changed direct dependencies) [descending]
//     (i.e. more efficient first)
//  2. number of fixed vulns [descending]
//  3. number of changed direct dependencies [ascending]
//  4. changed direct dependency name package names [ascending]
//  5. size of changed direct dependency bump [ascending]
func (a Patch) Compare(b Patch, sys semver.System) int {
	// 1. (fixed - introduced) / (changes) [desc]
	// Multiply out to avoid float casts
	aRatio := (len(a.Fixed) - len(a.Introduced)) * (len(b.PackageUpdates))
	bRatio := (len(b.Fixed) - len(b.Introduced)) * (len(a.PackageUpdates))
	if c := cmp.Compare(aRatio, bRatio); c != 0 {
		return -c
	}

	// 2. number of fixed vulns [desc]
	if c := cmp.Compare(len(a.Fixed), len(b.Fixed)); c != 0 {
		return -c
	}

	// 3. number of changed deps [asc]
	if c := cmp.Compare(len(a.PackageUpdates), len(b.PackageUpdates)); c != 0 {
		return c
	}

	// 4. changed names [asc]
	for i, aDep := range a.PackageUpdates {
		bDep := b.PackageUpdates[i]
		if c := cmp.Compare(aDep.Name, bDep.Name); c != 0 {
			return c
		}
	}

	// 5. dependency bump amount [asc]
	for i, aDep := range a.PackageUpdates {
		bDep := b.PackageUpdates[i]
		aVer, aErr := sys.Parse(aDep.VersionTo)
		bVer, bErr := sys.Parse(bDep.VersionTo)
		if aErr != nil || bErr != nil {
			// Versions don't parse as single versions, most likely a range from relax.
			// We can't easily compare the bounds of the range, so just do a string comparison.
			if c := cmp.Compare(aDep.VersionTo, bDep.VersionTo); c != 0 {
				return c
			}
			continue
		}

		if c := aVer.Compare(bVer); c != 0 {
			return c
		}
	}

	return 0
}

// Package represents a package that was found in a project.
type Package struct {
	Name    string `json:"name"`           // name of the dependency.
	Version string `json:"version"`        // version of the dependency in the graph.
	PURL    string `json:"purl,omitempty"` // PURL of the package & version.
}

// PackageUpdate represents a package that was updated by a patch.
type PackageUpdate struct {
	Name        string `json:"name"`        // name of dependency being updated.
	VersionFrom string `json:"versionFrom"` // version of the dependency before the patch.
	VersionTo   string `json:"versionTo"`   // version of the dependency after the patch.
	PURLFrom    string `json:"purlFrom"`    // PURL of the dependency before the patch.
	PURLTo      string `json:"purlTo"`      // PURL of the dependency after the patch.
	Transitive  bool   `json:"transitive"`  // false if this package is a direct dependency, true if indirect.

	Type dep.Type `json:"-"`
}

// ResolveError represents an error encountered during the initial resolution of the dependency graph.
//
// e.g.
//
//	ResolveError{
//		  Package:     OutputPackage{"foo", "1.2.3"},
//		  Requirement: OutputPackage{"bar", ">2.0.0"},
//		  Error:       "could not find a version that satisfies requirement >2.0.0 for package bar",
//	}
type ResolveError struct {
	Package     Package `json:"package"`     // the package that caused the error.
	Requirement Package `json:"requirement"` // the requirement of the package that errored.
	Error       string  `json:"error"`       // the error string.
}
