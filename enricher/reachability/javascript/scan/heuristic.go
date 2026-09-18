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

package scan

import (
	"sort"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/internal"
)

// Heuristic governs the scope of one Phase 2 scan attempt.
type Heuristic interface {
	Name() string
	IncludePackages(vulns []*internal.VulnRef) []string
	MaxIndirections() int
	SplitInBuckets() bool
}

// VulnPathOnly is the default heuristic. Scope = packages on the transitive
// path from root to each vulnerable leaf, leaf excluded. First-choice.
type VulnPathOnly struct {
	// VulnPathPackages maps each VulnRef pointer to the list of packages
	// on its root→leaf path. Keying by pointer (rather than OSVID)
	// preserves per-VulnRef paths when two VulnRefs share one CVE id —
	// e.g. the same CVE affecting two installed packages, whose paths
	// can differ.
	VulnPathPackages map[*internal.VulnRef][]string
}

// Name returns the heuristic name.
func (VulnPathOnly) Name() string { return "VULN_PATH_ONLY" }

// IncludePackages returns the union of path packages across the input
// vulns, excluding each vuln's OWN leaf only — not other vulns' leaves.
// Jelly's import resolution can still load the excluded leaf at scan time,
// and excluding other vulns' leaves from a shared transitive path (e.g.
// vuln-in-A reached via … → B → A when vuln-in-B is also in the bucket)
// would prevent jelly from traversing through B to reach A, producing a
// false-unreachable.
func (h VulnPathOnly) IncludePackages(vulns []*internal.VulnRef) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range vulns {
		ownLeaf := v.PackageName
		for _, p := range h.VulnPathPackages[v] {
			if p == ownLeaf || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out) // deterministic argv
	return out
}

// MaxIndirections returns the pointer-analysis depth limit.
func (VulnPathOnly) MaxIndirections() int { return 5 }

// SplitInBuckets allows recursive bucket-split on timeout.
func (VulnPathOnly) SplitInBuckets() bool { return true }

// IgnoreDeps is the fallback heuristic. Scope = none (jelly treats deps
// opaque). Used when VulnPathOnly scoping breaks reachability.
type IgnoreDeps struct{}

// Name returns the heuristic name.
func (IgnoreDeps) Name() string { return "IGNORE_DEPS" }

// IncludePackages returns a sentinel name that matches nothing, which
// causes jelly to treat all dependencies as opaque packages. The sentinel
// approach is preferred over --ignore-dependencies because it preserves
// jelly's import-graph for Phase 1 use while still excluding deps from
// the deep scan.
func (IgnoreDeps) IncludePackages(vulns []*internal.VulnRef) []string {
	return []string{"__scalibr_sentinel_no_such_pkg__"}
}

// MaxIndirections returns a smaller depth limit for this fallback mode.
func (IgnoreDeps) MaxIndirections() int { return 3 }

// SplitInBuckets returns false: this heuristic does not benefit from split.
func (IgnoreDeps) SplitInBuckets() bool { return false }
