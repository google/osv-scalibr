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

// Package materialize implements Phase 0 — npm dependency materialization.
// It stages a resolved node_modules tree for Jelly to walk, either by
// reusing a pre-existing one or by running `npm pack` against a subset of
// the dependency graph and laying out the tarballs with npm's hoisting
// rules.
package materialize

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/internal"
)

// nodeKey is the multi-version-safe identifier used internally by
// Materialize. Two installed copies of the same package at different
// versions are distinct nodes.
func nodeKey(name, version string) string { return name + "@" + version }

// Spec is the input to Materialize.
type Spec struct {
	SubprojectRoot string
	// ResolvedGraph is the dep graph (from scalibr's inventory). Nil means
	// "no materialization needed" — the caller already has node_modules or
	// there are no deps to install. Materialize will still detect and use
	// a pre-existing node_modules if present.
	ResolvedGraph *DepGraph
	// InstallSet is the subset of ResolvedGraph's packages the caller wants
	// installed. Empty with a non-nil ResolvedGraph means "install all".
	InstallSet []string
}

// DepGraph is the resolved dependency graph, typically built from scalibr's
// inv.Packages inside the Enricher.
type DepGraph struct {
	// Nodes maps package-install-id → package metadata.
	Nodes map[string]*DepNode
	// DirectDeps is the list of node IDs that are direct deps of the root.
	DirectDeps []string
}

// DepNode is one resolved package in the graph.
type DepNode struct {
	ID      string // arbitrary unique id in the graph
	Name    string
	Version string
	// Dependencies are IDs of other nodes in Nodes.
	Dependencies []string
	// PackageJSONDeps are package.json `dependencies` (name → version spec)
	// from the package, used for alias detection in placement. May be nil
	// if unknown.
	PackageJSONDeps map[string]string
}

// Layout is the result of Materialize.
type Layout struct {
	NodeModulesPath string
	StagingPath     string // <root>/node_modules/.jelly; empty if CreatedByUs=false
	// FailedPackages lists (name, version) pairs that npm pack failed to
	// fetch. These are absent from the materialized tree; downstream scan
	// results for vulns rooted in these packages should be treated as
	// "skipped, unknown" — never as "unreachable".
	FailedPackages []internal.FailedPackage
	CreatedByUs    bool // if true, Cleanup will rm -rf NodeModulesPath
}

// Materialize stages a node_modules tree for Jelly by downloading,
// extracting, and hardlinking the subset of the dep graph the caller
// requested. On failure during steps 0.b-0.g, the partial NodeModulesPath
// is removed so the next call doesn't trip the pre-existing gate at 0.a.
func Materialize(ctx context.Context, spec Spec) (*Layout, error) {
	nm := filepath.Join(spec.SubprojectRoot, "node_modules")

	// Step 0.a: pre-existing gate.
	if st, err := os.Stat(nm); err == nil && st.IsDir() {
		return &Layout{NodeModulesPath: nm, CreatedByUs: false}, nil
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat node_modules: %w", err)
	}
	if spec.ResolvedGraph == nil {
		return &Layout{NodeModulesPath: nm, CreatedByUs: false}, nil
	}

	// 0.b: decide install set.
	installNodes := selectInstallNodes(spec.ResolvedGraph, spec.InstallSet)
	packSpecs := make([]PackSpec, 0, len(installNodes))
	for _, n := range installNodes {
		packSpecs = append(packSpecs, PackSpec{Name: n.Name, Version: n.Version})
	}

	tmpDir, err := os.MkdirTemp("", "scalibr-jelly-pack-")
	if err != nil {
		return nil, fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Roll back the (initially empty) node_modules tree if any subsequent
	// step fails — otherwise the next invocation hits the pre-existing
	// gate above and silently skips the install.
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(nm)
		}
	}()

	// 0.c: download.
	tarballs, failed, err := DownloadTarballs(ctx, tmpDir, packSpecs)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}

	// 0.d: extract.
	stagingDir := filepath.Join(nm, ".jelly")
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir staging: %w", err)
	}
	metas := make([]*PackageMeta, 0, len(tarballs))
	for _, tb := range tarballs {
		pkgStagingDir := filepath.Join(stagingDir,
			fmt.Sprintf("%s@%s", strings.ReplaceAll(tb.Spec.Name, "/", "+"), tb.Spec.Version))
		extractTo := filepath.Join(pkgStagingDir, "node_modules", tb.Spec.Name)
		if err := ExtractTarball(tb.TarPath, extractTo); err != nil {
			return nil, fmt.Errorf("extract %s: %w", tb.Spec.Name, err)
		}
		pkgDeps := readPackageJSONDeps(extractTo)
		metas = append(metas, &PackageMeta{
			Name:            tb.Spec.Name,
			Version:         tb.Spec.Version,
			Dir:             extractTo,
			PackageJSONDeps: pkgDeps,
		})
	}

	// 0.e: graph edges from spec.ResolvedGraph. Keys are name@version so
	// multiple copies of one package at different versions stay distinct.
	// Metas whose findNode returns nil are unplaceable (the graph is
	// inconsistent) and are excluded from placement by clearing their
	// Parents and gating Parents writes against the unplaceable set. The
	// full metas slice (not a subset) is passed to ComputePlacements so
	// the integer indices encoded in Parents stay valid.
	keyToIdx := map[string]int{}
	unplaceable := make(map[int]bool, len(metas))
	for i, m := range metas {
		key := nodeKey(m.Name, m.Version)
		// Two metas with the same (name, version) collapse via
		// keyToIdx's last-writer-wins: the earlier copy would silently
		// get no edges and no Placement, while the later copy is
		// placed normally. Mark the loser unplaceable so its Parents
		// can't accumulate phantom edges, but do NOT append to failed:
		// the WINNER serves all vulns at this (name, version) from
		// node_modules, so emitting FailedPackage would over-skip
		// vulns whose code IS on disk.
		if prev, dup := keyToIdx[key]; dup {
			unplaceable[prev] = true
		}
		keyToIdx[key] = i + 1 // offset: 0 = synthetic root
	}
	for i, m := range metas {
		// Skip metas already marked unplaceable above to avoid emitting
		// duplicate FailedPackage entries when findNode also returns
		// nil for an already-flagged dup loser.
		if unplaceable[i+1] {
			continue
		}
		if findNode(spec.ResolvedGraph, m.Name, m.Version) == nil {
			unplaceable[i+1] = true
			failed = append(failed, internal.FailedPackage{Name: m.Name, Version: m.Version})
		}
	}
	for _, m := range metas {
		node := findNode(spec.ResolvedGraph, m.Name, m.Version)
		if node == nil {
			continue
		}
		for _, depID := range node.Dependencies {
			depNode := spec.ResolvedGraph.Nodes[depID]
			if depNode == nil {
				continue
			}
			depIdx, ok := keyToIdx[nodeKey(depNode.Name, depNode.Version)]
			if !ok {
				continue
			}
			// Don't list an unplaceable meta as a parent — placeSCC
			// would otherwise try to dereference it and emit a
			// placement under its (non-installed) directory.
			if unplaceable[depIdx] {
				continue
			}
			// depNode lists m as a parent.
			metas[depIdx-1].Parents = append(metas[depIdx-1].Parents, keyToIdx[nodeKey(m.Name, m.Version)])
		}
	}
	// Direct deps get synthetic-root parent (unless the dep itself is
	// unplaceable — same reason as above).
	for _, id := range spec.ResolvedGraph.DirectDeps {
		dn := spec.ResolvedGraph.Nodes[id]
		if dn == nil {
			continue
		}
		idx, ok := keyToIdx[nodeKey(dn.Name, dn.Version)]
		if !ok || unplaceable[idx] {
			continue
		}
		metas[idx-1].Parents = append(metas[idx-1].Parents, 0)
	}

	// 0.f: placements. Pass the FULL metas slice so the int indices in
	// Parents (which are metas-space) remain valid. Unplaceable metas
	// have no Parents (nothing gated them in) so placeSCC produces no
	// placement for them.
	placements := ComputePlacements(metas, nm)

	// Detect placement losers: metas that placeSCC touched but whose
	// every target was claimed first by another meta. ComputePlacements
	// records them with empty TargetPaths so we can surface them as
	// FailedPackage — otherwise the scan layer wouldn't skip vulns
	// rooted in a package whose code is in staging but not in the
	// hard-linked node_modules layout.
	for _, p := range placements {
		if len(p.TargetPaths) == 0 {
			failed = append(failed, internal.FailedPackage{Name: p.Meta.Name, Version: p.Meta.Version})
		}
	}

	// 0.g: hardlink.
	for _, p := range placements {
		for _, target := range p.TargetPaths {
			if err := HardlinkTree(p.Meta.Dir, target); err != nil {
				return nil, fmt.Errorf("hardlink %s → %s: %w", p.Meta.Dir, target, err)
			}
		}
	}

	success = true
	return &Layout{
		NodeModulesPath: nm,
		StagingPath:     stagingDir,
		FailedPackages:  failed,
		CreatedByUs:     true,
	}, nil
}

// selectInstallNodes picks the subset of graph nodes we'll install.
// Empty installSet means "install everything". Output is sorted by
// (name, version) so downstream graph construction (and any test that
// observes the order) is deterministic.
func selectInstallNodes(g *DepGraph, installSet []string) []*DepNode {
	out := make([]*DepNode, 0, len(g.Nodes))
	if len(installSet) == 0 {
		for _, n := range g.Nodes {
			out = append(out, n)
		}
	} else {
		want := map[string]bool{}
		for _, n := range installSet {
			want[n] = true
		}
		for _, n := range g.Nodes {
			if want[n.Name] {
				out = append(out, n)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// findNode returns the DepGraph node for a given (name, version) pair, or
// nil if no match. Multi-version safe.
func findNode(g *DepGraph, name, version string) *DepNode {
	for _, n := range g.Nodes {
		if n.Name == name && n.Version == version {
			return n
		}
	}
	return nil
}

// readPackageJSONDeps reads dependencies from <dir>/package.json. Returns
// nil if the file is missing or malformed (best-effort; placement fallback
// handles missing deps).
func readPackageJSONDeps(dir string) map[string]string {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pj struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &pj); err != nil {
		return nil
	}
	return pj.Dependencies
}

// Cleanup removes the materialized node_modules if we created it.
func (l *Layout) Cleanup() error {
	if l == nil || !l.CreatedByUs {
		return nil
	}
	return os.RemoveAll(l.NodeModulesPath)
}
