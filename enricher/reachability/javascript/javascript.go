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

// Package javascript provides an Enricher that uses the Jelly static
// analyzer to determine whether npm-ecosystem vulnerabilities are reachable
// from the project being scanned.
package javascript

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/corpus"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/depgraph"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/entrypoints"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/internal"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/jelly"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/materialize"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/scan"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the unique name of this enricher.
const Name = "reachability/javascript"

// defaultMaxFileSize bounds the size of any individual source file Jelly
// will analyze. 512 KiB is large enough for any legitimate hand-written
// module, small enough to skip minified vendor bundles that would otherwise
// dominate analysis time and memory.
const defaultMaxFileSize int64 = 524288

// Config bundles the enricher's runtime options.
type Config struct {
	MetadataFile   string // path to corpus.json produced by reachability project
	SubprojectRoot string // default "." (CWD); tests override
}

// Enricher is the JavaScript/npm reachability enricher.
type Enricher struct {
	cfg         Config
	jellyClient jelly.Client // nil means use realClient
}

// NewWithConfig constructs an Enricher with explicit config (for tests and
// future wiring from PluginConfig).
func NewWithConfig(cfg Config) *Enricher {
	return &Enricher{cfg: cfg}
}

// NewWithConfigAndClient is the test-seam constructor that injects a
// custom Jelly client.
func NewWithConfigAndClient(cfg Config, client jelly.Client) *Enricher {
	return &Enricher{cfg: cfg, jellyClient: client}
}

// Name returns the enricher name.
func (Enricher) Name() string { return Name }

// Version returns the enricher version.
func (Enricher) Version() int { return 0 }

// Requirements returns the plugin capabilities.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network:            plugin.NetworkOnline,
		DirectFS:           true,
		RunningSystem:      true,
		AllowUnsafePlugins: true,
	}
}

// RequiredPlugins returns the plugins this enricher depends on. The vulnmatch
// enricher is required so inv.PackageVulns is populated before we run.
func (Enricher) RequiredPlugins() []string {
	return []string{packagelockjson.Name, pnpmlock.Name, yarnlock.Name, osvdev.Name}
}

// New constructs a new Enricher. cfg is currently unused; metadata-file path
// is read from the SCALIBR_JELLY_METADATA_FILE environment variable until
// PluginConfig proto wiring is added.
func New(cfg *cpb.PluginConfig) (enricher.Enricher, error) {
	return NewWithConfig(Config{
		MetadataFile: os.Getenv("SCALIBR_JELLY_METADATA_FILE"),
	}), nil
}

// Enrich runs the reachability pipeline.
//
// Skips with nil only when prerequisites legitimately aren't met (no
// configured metadata file, jelly toolchain absent, no in-scope vulns).
// Configuration mistakes (corpus parse failure) and runtime failures
// (materialize, scan) propagate as errors so operators see a non-SUCCEEDED
// plugin status rather than silent no-op.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	if e.cfg.MetadataFile == "" {
		log.Debug("reachability/javascript: SCALIBR_JELLY_METADATA_FILE not set, skipping")
		return nil
	}
	client := e.jellyClient
	if client == nil {
		client = jelly.NewRealClient()
	}
	if !client.Available(ctx) {
		log.Info("reachability/javascript: jelly toolchain not available, skipping")
		return nil
	}

	corp, err := corpus.Load(e.cfg.MetadataFile)
	if err != nil {
		return fmt.Errorf("corpus load: %w", err)
	}

	// Select in-scope vulns.
	var in []*internal.VulnRef
	var backrefs []*inventory.PackageVuln
	for _, pv := range inv.PackageVulns {
		if pv.Package == nil || pv.Vulnerability == nil {
			continue
		}
		entries, ok := corp.Lookup(pv.Vulnerability.Id)
		if !ok {
			continue
		}
		var patterns []string
		for _, ent := range entries {
			patterns = append(patterns, ent.Patterns...)
		}
		in = append(in, &internal.VulnRef{
			OSVID:              pv.Vulnerability.Id,
			PackageName:        pv.Package.Name,
			PackageVersion:     pv.Package.Version,
			AccessPathPatterns: patterns,
		})
		backrefs = append(backrefs, pv)
	}
	if len(in) == 0 {
		return nil
	}

	root := e.cfg.SubprojectRoot
	if root == "" && input != nil && input.ScanRoot != nil {
		root = input.ScanRoot.Path
	}
	if root == "" {
		root = "."
	}

	// Phase 0: materialize (uses pre-existing node_modules if present).
	layout, err := materialize.Materialize(ctx, materialize.Spec{
		SubprojectRoot: root,
	})
	if err != nil {
		return fmt.Errorf("materialize: %w", err)
	}
	defer func() {
		if err := layout.Cleanup(); err != nil {
			log.Warnf("reachability/javascript: layout cleanup: %v", err)
		}
	}()

	// Phase 1+2: scan. Try VulnPathOnly first (narrow scope by walking
	// node_modules for each vuln's path packages); on graph build failure
	// or empty graph, that heuristic emits an empty include set which
	// degrades to "scan only the leaf" — IgnoreDeps as the chained fallback
	// is what actually rescues those cases.
	heuristics, missingFromGraph := buildHeuristics(root, in)
	failed := append([]internal.FailedPackage(nil), layout.FailedPackages...)
	failed = append(failed, missingFromGraph...)
	orch := &scan.Orchestrator{
		Client:         client,
		Corpus:         corp,
		BaseDir:        root,
		Heuristics:     heuristics,
		Timeouts:       scan.DefaultTimeouts(),
		FailedPackages: failed,
		MaxFileSize:    defaultMaxFileSize,
		EntryPoints:    entrypoints.Infer(root),
		ExcludeEntries: stagingExcludes(layout),
	}
	results, err := orch.Scan(ctx, in)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// Map results back to PackageVulns by VulnRef pointer identity. Keying
	// by OSVID would collapse two PackageVulns sharing the same CVE id
	// (e.g. the same CVE present in two installed packages) into a single
	// verdict, misattributing one package's reachability to the other.
	byRef := make(map[*internal.VulnRef]*internal.Result, len(results))
	for _, r := range results {
		if r != nil && r.Ref != nil {
			byRef[r.Ref] = r
		}
	}
	for i, pv := range backrefs {
		r, ok := byRef[in[i]]
		if !ok || r == nil {
			continue
		}
		if r.Skipped {
			log.Debugf("reachability/javascript: %s skipped: %s", r.OSVID, r.SkipReason)
			continue
		}
		if !r.Reachable && !hasOurSignal(pv.ExploitabilitySignals) {
			pv.ExploitabilitySignals = append(pv.ExploitabilitySignals, &vex.FindingExploitabilitySignal{
				Plugin:        Name,
				Justification: vex.VulnerableCodeNotInExecutePath,
			})
		}
	}
	return nil
}

// stagingExcludes returns the jelly --exclude-entries arguments needed to
// keep the materializer's hardlink-staging tree (and any stale one from a
// previous SIGKILLed run) out of the analysis surface.
//
// When Layout.StagingPath is non-empty it's used to derive a project-
// relative form (basename + `/<base>/**`) so any future change to the
// staging directory name in materialize is honored automatically.
// Otherwise the static `node_modules/.jelly` default is emitted to
// guard against stale staging trees left behind by previous runs.
//
// Returns RELATIVE paths under the project root rather than absolute
// ones: jelly's glob library treats `[`, `]`, `*`, `?`, `{`, `}` as
// metacharacters, so a project path containing those (CI workspace
// dirs are a frequent culprit, e.g. /tmp/build[123]/) would silently
// defeat an absolute-path exclude.
func stagingExcludes(l *materialize.Layout) []string {
	rel := "node_modules/.jelly"
	if l != nil && l.StagingPath != "" {
		// StagingPath is <root>/node_modules/<basename>. Derive the
		// project-relative form so the exclude matches even if the
		// staging dir name changes in the future.
		base := filepath.Base(l.StagingPath)
		if base != "" && base != "." && base != "/" {
			rel = "node_modules/" + base
		}
	}
	return []string{rel, rel + "/**"}
}

// nameInGraph reports whether ANY node with the given package name is
// present in the graph (regardless of root-reachability). Used by the
// empty-version FailedPackage gate so we don't issue a nameOnly
// wholesale-skip when a copy of the package IS on disk — even if that
// copy is orphaned, peers at other concrete versions may still be
// analyzable.
func nameInGraph(g *depgraph.Graph, name string) bool {
	if g == nil {
		return false
	}
	for _, n := range g.Nodes {
		if n.Name == name {
			return true
		}
	}
	return false
}

// hasOurSignal reports whether this enricher has already attached a signal
// to a PackageVuln. Guards Enrich against duplicating signals when the
// enricher is invoked twice on the same Inventory (test harness, retry).
func hasOurSignal(sigs []*vex.FindingExploitabilitySignal) bool {
	for _, s := range sigs {
		if s != nil && s.Plugin == Name {
			return true
		}
	}
	return false
}

// buildHeuristics returns the scan heuristic chain AND the list of vuln
// leaf packages that are absent (or orphaned) in the on-disk dep graph.
// The latter feeds Orchestrator.FailedPackages so vulns whose code is
// either missing OR not reachable from any project root get Skipped
// instead of silently marked unreachable.
//
// Empty-version vulns are NOT added to the missing list — partition's
// version-blind name-only path would then suppress every other vuln of
// the same name (including ones with concrete on-disk versions). We
// can't classify them confidently, so let them flow through the
// heuristic chain.
//
// VulnPathOnly is first when at least one vuln has a usable path; the
// last entry is always IgnoreDeps as the safe fallback (jelly treats
// dependencies as opaque). When depgraph.Build returns nil (no
// node_modules), we can't trust missing-leaf detection and return no
// FailedPackages.
func buildHeuristics(root string, vulns []*internal.VulnRef) ([]scan.Heuristic, []internal.FailedPackage) {
	graph, err := depgraph.Build(root)
	if err != nil || graph == nil {
		if err != nil {
			log.Debugf("reachability/javascript: depgraph.Build failed: %v", err)
		}
		return []scan.Heuristic{scan.IgnoreDeps{}}, nil
	}
	// Per-VulnRef path map (keyed by pointer, not OSVID) so that two
	// VulnRefs sharing one CVE id but living in different installed
	// packages don't collide and overwrite each other's path list.
	vulnPaths := make(map[*internal.VulnRef][]string, len(vulns))
	var missing []internal.FailedPackage
	haveUsablePath := false
	for _, v := range vulns {
		if v.PackageVersion == "" {
			// Empty version is ambiguous — we can't classify a specific
			// installed copy. Only mark missing if NO version of this
			// name is installed at all. We MUST NOT key this on
			// IsReachable (orphan-but-installed packages are not
			// reachable from a root yet are present on disk — the
			// nameOnly skip would then suppress vulns at concrete
			// versions of the SAME name that ARE reachable).
			if !nameInGraph(graph, v.PackageName) {
				missing = append(missing, internal.FailedPackage{Name: v.PackageName})
			}
			continue
		}
		// Version-precise checks: avoid the multi-version trap where
		// foo@1 is reachable and foo@2 is orphaned. IsReachableKey and
		// PathsToLeafKey both pin to the exact installed copy this vuln
		// targets.
		if !graph.IsReachableKey(v.PackageName, v.PackageVersion) {
			missing = append(missing, internal.FailedPackage{
				Name:    v.PackageName,
				Version: v.PackageVersion,
			})
			continue
		}
		paths := graph.PathsToLeafKey(v.PackageName, v.PackageVersion)
		if len(paths) > 0 {
			vulnPaths[v] = paths
		}
		haveUsablePath = true
	}
	if !haveUsablePath {
		return []scan.Heuristic{scan.IgnoreDeps{}}, missing
	}
	return []scan.Heuristic{
		scan.VulnPathOnly{VulnPathPackages: vulnPaths},
		scan.IgnoreDeps{},
	}, missing
}
