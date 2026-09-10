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

package materialize

import (
	"path/filepath"
	"sort"
	"strings"
)

// PackageMeta is the internal package-graph node used for placement.
//
// Parents encodes the dep-graph edges: 0 = synthetic project root;
// positive N = metas[N-1].
type PackageMeta struct {
	Name            string
	Version         string
	Dir             string            // extracted staging dir
	PackageJSONDeps map[string]string // from <Dir>/package.json's dependencies
	Parents         []int
}

// Placement is one {package, target-paths} pairing.
type Placement struct {
	Meta        *PackageMeta
	TargetPaths []string
}

// ComputePlacements decides where each package should appear in the
// node_modules tree, respecting npm hoisting rules. See JELLY.md §3 Phase 0.f.
//
// Cross-meta target-path collisions (e.g. two multi-version metas both
// rooted at synthetic root via aliases, which would resolve to the same
// `<nm>/<name>` slot) are detected at record time: the first claimant
// wins; subsequent claims are silently dropped from THIS meta's
// TargetPaths so HardlinkTree doesn't attempt a duplicate os.Link
// that sameInode can't reconcile. The losing meta still appears in the
// output with empty TargetPaths so callers can distinguish "wasn't
// placed" (entry present, TargetPaths empty) from "didn't exist"
// (entry absent).
func ComputePlacements(metas []*PackageMeta, nodeModulesDir string) []Placement {
	placements := map[*PackageMeta]map[string]bool{}
	claimedTargets := map[string]bool{}
	record := func(m *PackageMeta, dir string) {
		// Always register the meta in placements (with an empty set if
		// every target collides) so the returned slice contains an
		// entry for every meta touched by placeSCC. materialize.go uses
		// the empty-TargetPaths shape to surface placement-lost metas
		// as FailedPackage.
		s := placements[m]
		if s == nil {
			s = map[string]bool{}
			placements[m] = s
		}
		if claimedTargets[dir] {
			return // another meta already won this target path
		}
		claimedTargets[dir] = true
		s[dir] = true
	}
	multiVersion := findMultiVersionNames(metas)

	sccs := TarjanSCC(metas)
	for _, scc := range sccs {
		placeSCC(metas, scc, nodeModulesDir, multiVersion, record)
	}

	// Sort the per-meta target paths and the placements slice itself so
	// HardlinkTree's call order is deterministic. Without this, the
	// nondeterministic map iteration causes intermittent EEXIST flakes when
	// two metas hash to the same target path on different runs.
	out := make([]Placement, 0, len(placements))
	for m, set := range placements {
		paths := make([]string, 0, len(set))
		for p := range set {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		out = append(out, Placement{Meta: m, TargetPaths: paths})
	}
	// SliceStable so two metas with identical Name+Version (constructible
	// when the same package appears under two distinct DepGraph IDs —
	// hoisted transitive vs direct dep) retain a deterministic order
	// across runs.
	sort.SliceStable(out, func(i, j int) bool {
		ki := out[i].Meta.Name + "@" + out[i].Meta.Version
		kj := out[j].Meta.Name + "@" + out[j].Meta.Version
		return ki < kj
	})
	return out
}

func placeSCC(metas []*PackageMeta, scc []int, nodeModulesDir string, multiVersion map[string]bool, record func(*PackageMeta, string)) {
	// V1: each package in the SCC is placed at the top-level unless a parent
	// depends on a different version, or this name has multiple installed
	// versions across the graph (force-nest).
	for _, idx := range scc {
		m := metas[idx]
		if multiVersion[m.Name] {
			for _, parentIdx := range m.Parents {
				if parentIdx == 0 {
					record(m, filepath.Join(nodeModulesDir, m.Name))
					continue
				}
				parent := metas[parentIdx-1]
				parentDir := filepath.Join(nodeModulesDir, parent.Name)
				record(m, filepath.Join(parentDir, "node_modules", resolvedInstallName(parent, m)))
			}
			continue
		}
		for _, parentIdx := range m.Parents {
			if parentIdx == 0 {
				record(m, filepath.Join(nodeModulesDir, m.Name))
				continue
			}
			parent := metas[parentIdx-1]
			if hasVersionConflict(parent, m) {
				parentDir := filepath.Join(nodeModulesDir, parent.Name)
				record(m, filepath.Join(parentDir, "node_modules", resolvedInstallName(parent, m)))
			} else {
				record(m, filepath.Join(nodeModulesDir, resolvedInstallName(parent, m)))
			}
		}
	}
}

func hasVersionConflict(parent, child *PackageMeta) bool {
	if parent.PackageJSONDeps == nil {
		return false
	}
	spec, ok := parent.PackageJSONDeps[child.Name]
	if !ok {
		return false
	}
	if child.Version == "" {
		return false
	}
	// Pragmatic v1: treat "spec doesn't contain installed version" as conflict.
	// A real semver-range satisfier comes later.
	return !strings.Contains(spec, child.Version)
}

func findMultiVersionNames(metas []*PackageMeta) map[string]bool {
	seen := map[string]string{}
	multi := map[string]bool{}
	for _, m := range metas {
		if existing, ok := seen[m.Name]; ok && existing != m.Version {
			multi[m.Name] = true
		} else {
			seen[m.Name] = m.Version
		}
	}
	return multi
}

// resolvedInstallName inspects the parent's package.json dependencies for
// an `npm:real@ver` entry matching child; if found, returns the alias key.
// Otherwise returns the child's real name. Multiple aliases pointing at the
// same npm:real@ver tie-break by lexicographic order so the chosen
// install-name is deterministic across runs.
func resolvedInstallName(parent, child *PackageMeta) string {
	if parent == nil || parent.PackageJSONDeps == nil {
		return child.Name
	}
	var matches []string
	for alias, spec := range parent.PackageJSONDeps {
		if strings.HasPrefix(spec, "npm:"+child.Name+"@") {
			matches = append(matches, alias)
		}
	}
	if len(matches) == 0 {
		return child.Name
	}
	sort.Strings(matches)
	return matches[0]
}

// TarjanSCC runs Tarjan's strongly-connected-components algorithm on the
// package-metadata graph (using Parents as edges).
func TarjanSCC(metas []*PackageMeta) [][]int {
	n := len(metas)
	index := make([]int, n)
	lowlink := make([]int, n)
	onStack := make([]bool, n)
	for i := range index {
		index[i] = -1
	}
	var stack []int
	var sccs [][]int
	var idx int

	var strong func(v int)
	strong = func(v int) {
		index[v] = idx
		lowlink[v] = idx
		idx++
		stack = append(stack, v)
		onStack[v] = true

		for _, p := range metas[v].Parents {
			if p == 0 {
				continue // synthetic root
			}
			w := p - 1
			if w < 0 || w >= n {
				continue
			}
			if index[w] == -1 {
				strong(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] && index[w] < lowlink[v] {
				lowlink[v] = index[w]
			}
		}

		if lowlink[v] == index[v] {
			var scc []int
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, scc)
		}
	}

	for v := range n {
		if index[v] == -1 {
			strong(v)
		}
	}
	return sccs
}
