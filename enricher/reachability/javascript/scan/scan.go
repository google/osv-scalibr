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

// Package scan orchestrates Phase 1 (import-reachability pre-pass) and
// Phase 2 (heuristic-chain + bucket-split) scans against Jelly.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/corpus"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/internal"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/jelly"
	"github.com/google/osv-scalibr/log"
)

// Orchestrator runs Phase 1 + Phase 2 against the given Jelly Client.
type Orchestrator struct {
	Client     jelly.Client
	Corpus     *corpus.Corpus
	Heuristics []Heuristic
	Timeouts   TimeoutConfig
	BaseDir    string
	// FailedPackages are (name, version) pairs that Phase 0 materialization
	// couldn't fetch / install — also extended by the Enricher with vulns
	// whose package isn't present on disk after Materialize. Vulns whose
	// (PackageName, PackageVersion) matches are skipped (not analyzed,
	// not marked unreachable) because without the package on disk jelly
	// silently reports no matches → false negative.
	FailedPackages []internal.FailedPackage
	// EntryPoints is the optional positional entry-point list passed to
	// jelly. Empty means "use the project root" (Jelly's whole-dir default).
	EntryPoints []string
	// MaxFileSize, if > 0, is forwarded as --max-file-size to bound Jelly's
	// per-file analysis cost.
	MaxFileSize int64
	// ExcludeEntries are paths/globs passed to jelly's --exclude-entries.
	// The enricher sets this to skip the materializer's staging tree
	// (node_modules/.jelly/…) so jelly doesn't double-count hard-linked
	// duplicates of installed packages as additional modules.
	ExcludeEntries []string
}

// TimeoutConfig tunes first-attempt and bucketed-retry timeouts.
type TimeoutConfig struct {
	AllVulnRuns  time.Duration
	BucketedRuns time.Duration
}

// DefaultTimeouts returns a conservative default (10min all-vuln, 3min bucketed).
func DefaultTimeouts() TimeoutConfig {
	return TimeoutConfig{
		AllVulnRuns:  10 * time.Minute,
		BucketedRuns: 3 * time.Minute,
	}
}

// Scan runs Phase 1 (import-reachability pre-pass) followed by Phase 2
// (heuristic chain + bucket-split) and returns per-vuln Results. Vulns
// rooted in FailedPackages are split off first and emitted as Skipped.
// Returns ctx.Err() promptly if cancellation arrives between phases.
func (o *Orchestrator) Scan(ctx context.Context, vulns []*internal.VulnRef) ([]*internal.Result, error) {
	scoped, skipped := o.partitionForFailedPackages(vulns)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	remaining, prunedResults, err := o.RunPhase1(ctx, scoped)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	phase2Results, err := o.RunPhase2(ctx, remaining)
	if err != nil {
		return nil, err
	}
	out := make([]*internal.Result, 0, len(vulns))
	out = append(out, skipped...)
	out = append(out, prunedResults...)
	out = append(out, phase2Results...)
	return out, nil
}

// partitionForFailedPackages splits vulns into (still-analyzable, Skipped).
// Matching is version-exact when the FailedPackage entry carries a Version
// (so foo@1.0.0-failed doesn't skip foo@2.0.0 vulns whose code is on disk)
// and name-only when Version is empty (a deliberate "all versions absent"
// signal callers can use for whole-package outages).
func (o *Orchestrator) partitionForFailedPackages(vulns []*internal.VulnRef) (keep []*internal.VulnRef, skipped []*internal.Result) {
	if len(o.FailedPackages) == 0 {
		return vulns, nil
	}
	versioned := make(map[string]bool, len(o.FailedPackages))
	nameOnly := make(map[string]bool, len(o.FailedPackages))
	for _, fp := range o.FailedPackages {
		if fp.Version == "" {
			nameOnly[fp.Name] = true
		} else {
			versioned[fp.Name+"@"+fp.Version] = true
		}
	}
	for _, v := range vulns {
		switch {
		case nameOnly[v.PackageName]:
			skipped = append(skipped, &internal.Result{
				Ref:        v,
				OSVID:      v.OSVID,
				Skipped:    true,
				SkipReason: "no installed version of package: " + v.PackageName,
			})
		case versioned[v.PackageName+"@"+v.PackageVersion]:
			skipped = append(skipped, &internal.Result{
				Ref:        v,
				OSVID:      v.OSVID,
				Skipped:    true,
				SkipReason: "package not installed: " + v.PackageName + "@" + v.PackageVersion,
			})
		default:
			keep = append(keep, v)
		}
	}
	return keep, skipped
}

// RunPhase1 performs the cheap import-reachability pre-pass and partitions
// the input vulns into (still-in-scope VulnRefs, provably-unreachable Results).
func (o *Orchestrator) RunPhase1(ctx context.Context, vulns []*internal.VulnRef) (remaining []*internal.VulnRef, prunedResults []*internal.Result, err error) {
	// Build include-packages from the first heuristic so Phase 1's scope
	// matches Phase 2's first attempt.
	var include []string
	if len(o.Heuristics) > 0 {
		include = o.Heuristics[0].IncludePackages(vulns)
	}
	tmpDir, err := os.MkdirTemp("", "scalibr-jelly-import-")
	if err != nil {
		return nil, nil, fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	reachOut := filepath.Join(tmpDir, "reach.json")

	res, err := o.Client.RunImportOnly(ctx, jelly.ImportOnlyArgs{
		BaseDir:          o.BaseDir,
		EntryPoints:      o.EntryPoints,
		IncludePackages:  include,
		ExcludeEntries:   o.ExcludeEntries,
		ReachableFileOut: reachOut,
		Timeout:          o.Timeouts.AllVulnRuns,
		MaxFileSize:      o.MaxFileSize,
	})
	if err != nil {
		// Parent-ctx cancellation propagates upward (errors.Is matches
		// because runJelly's classify() returned the parent ctx error
		// verbatim for terminationCanceled). Inner wall-clock timeouts
		// return *exec.ExitError, which does NOT satisfy errors.Is.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, err
		}
		// Advisory failure. The salvage path returned whatever partial
		// reachable-file jelly wrote before being killed. We can only
		// trust a NON-EMPTY result — an empty ReachablePackages from a
		// failed run is "no data" not "no deps reachable", and pruning
		// every token-bearing vuln against an empty set would emit
		// false-unreachable signals wholesale. Fall back to the no-
		// pruning baseline (the round-1 behavior) so Phase 2 still
		// runs against the full vuln set.
		if len(res.ReachablePackages) == 0 {
			return vulns, nil, nil
		}
		// Partial salvage: continue to the prune loop. Vulns whose
		// tokens match the partial set get pruned; others stay in
		// remaining for Phase 2.
	}

	for _, v := range vulns {
		if anyAccessPathReachable(v.AccessPathPatterns, res.ReachablePackages) {
			remaining = append(remaining, v)
		} else {
			prunedResults = append(prunedResults, &internal.Result{
				Ref:       v,
				OSVID:     v.OSVID,
				Reachable: false,
				Skipped:   false,
			})
		}
	}
	return remaining, prunedResults, nil
}

// anyAccessPathReachable returns true if at least one access-path pattern
// is fully reachable. A vuln is pruned only when EVERY pattern misses —
// the conservative choice is to keep ambiguous vulns for the full Phase 2
// scan rather than dropping them at Phase 1.
func anyAccessPathReachable(patterns []string, reachable []jelly.ReachablePackage) bool {
	if len(patterns) == 0 {
		return true // no patterns = sentinel-loc match = can't judge; proceed
	}
	for _, p := range patterns {
		if AccessPathReachable(p, reachable) {
			return true
		}
	}
	return false
}

// RunOneBucket executes one Phase 2 scan for the given bucket. It writes
// the bucket's vulnerability patterns to a tmp file, invokes Jelly, parses
// the matches-file, and translates into per-vuln Results.
func (o *Orchestrator) RunOneBucket(ctx context.Context, b Bucket) ([]*internal.Result, error) {
	tmpDir, err := os.MkdirTemp("", "scalibr-jelly-bucket-")
	if err != nil {
		return nil, fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	vulnsFile := filepath.Join(tmpDir, "vulns.json")
	matchesFile := filepath.Join(tmpDir, "matches.json")
	diagFile := filepath.Join(tmpDir, "diag.json")

	if err := writeBucketVulns(vulnsFile, b.Vulns, o.Corpus); err != nil {
		return nil, err
	}

	res, err := o.Client.RunFullScan(ctx, jelly.FullScanArgs{
		BaseDir:             o.BaseDir,
		EntryPoints:         o.EntryPoints,
		VulnerabilitiesFile: vulnsFile,
		IncludePackages:     b.Heuristic.IncludePackages(b.Vulns),
		ExcludeEntries:      o.ExcludeEntries,
		MatchesFile:         matchesFile,
		DiagnosticsFile:     diagFile,
		Timeout:             b.Timeout,
		MaxIndirections:     b.Heuristic.MaxIndirections(),
		MaxFileSize:         o.MaxFileSize,
	})
	if err != nil {
		return nil, err
	}
	if res.TimedOut {
		// Wrap TerminationError into the sentinel so operators see the
		// real kill-signal / exit-status detail in "all heuristics
		// exhausted; last error: ..." messages — symmetric with the
		// TerminatedEarly branch below.
		if res.TerminationError != nil {
			return nil, fmt.Errorf("%w: %w", ErrBucketTimeout, res.TerminationError)
		}
		return nil, ErrBucketTimeout
	}
	// Subprocess produced output but Diagnostics flagged abort/lowmem/range
	// or RunFullScan inferred TerminatedEarly from a non-zero exit. Treat
	// the empty matches as untrustworthy — never as authoritative
	// "unreachable". Surface as a non-timeout error so RunPhase2 advances
	// heuristics rather than uselessly bucket-splitting. Wrap the
	// underlying TerminationError so operators see the real cause
	// (missing binary, OOM kill, etc.) instead of just "terminated early".
	if res.TerminatedEarly {
		if res.TerminationError != nil {
			return nil, fmt.Errorf("%w: %w", ErrBucketTerminatedEarly, res.TerminationError)
		}
		return nil, ErrBucketTerminatedEarly
	}

	// Success path. RunFullScan can populate TerminationError in a third
	// regime — Matches trusted (non-empty, analyzerRounds >= 2) but the
	// subprocess still errored on teardown (unhandled promise, deinit
	// SIGABRT). Neither TimedOut nor TerminatedEarly is set in that
	// regime, so the error would silently never surface. Log it so
	// operators have visibility that the run, while trusted, was noisy.
	if res.TerminationError != nil {
		log.Warnf("reachability/javascript: bucket trusted despite jelly exit error: %v", res.TerminationError)
	}
	out := make([]*internal.Result, 0, len(b.Vulns))
	for _, v := range b.Vulns {
		locs, analyzed := res.Matches[v.OSVID]
		r := &internal.Result{
			Ref:       v,
			OSVID:     v.OSVID,
			Reachable: len(locs) > 0,
			Skipped:   !analyzed,
		}
		if !analyzed {
			r.SkipReason = "vuln id absent from matches-file"
		}
		out = append(out, r)
	}
	return out, nil
}

// writeBucketVulns materializes the subset of corpus entries for this
// bucket's vulns into a JSON file Jelly can consume. The corpus lookup
// happens at most ONCE per OSV id even when multiple VulnRefs in the
// bucket share that id (one CVE matched against two installed packages):
// jelly's --vulnerabilities consumer is fed one record per (id, entry)
// rather than one per (id, entry, vuln-ref), avoiding duplicate ids in
// the output. The ?-vs-(cbarg) dedup runs across ALL entries belonging
// to one id — different corpus contributors can publish the two pattern
// shapes in separate entries that share an id, and keeping both would
// double-count the same callback as two matches at scan time.
func writeBucketVulns(path string, vulns []*internal.VulnRef, corp *corpus.Corpus) error {
	seenID := make(map[string]bool, len(vulns))
	var all []corpus.Entry
	for _, v := range vulns {
		if seenID[v.OSVID] {
			continue
		}
		entries, ok := corp.Lookup(v.OSVID)
		if !ok {
			continue
		}
		seenID[v.OSVID] = true
		// Union all patterns across this id's entries, then redistribute
		// the deduped set onto entries[0]; nil out the rest so jelly
		// receives one patterns-bearing record per id (still keeping
		// per-entry Loc data, which jelly indexes separately).
		var union []string
		for _, e := range entries {
			union = append(union, e.Patterns...)
		}
		deduped := dedupPatternsCbargWins(union)
		entriesCopy := append([]corpus.Entry(nil), entries...) // don't mutate corpus
		for i := range entriesCopy {
			if i == 0 {
				entriesCopy[i].Patterns = deduped
			} else {
				entriesCopy[i].Patterns = nil
			}
		}
		all = append(all, entriesCopy...)
	}
	raw, err := json.Marshal(all)
	if err != nil {
		return fmt.Errorf("marshal vuln patterns: %w", err)
	}
	return os.WriteFile(path, raw, 0o600)
}

// dedupPatternsCbargWins drops `?`-containing patterns when at least one
// `(cbarg)`-containing pattern is present in the same entry. The `?` form
// is a vague any-argument matcher; the `(cbarg)` form is the precise
// callback-argument variant. Keeping both double-counts the same reachable
// callback as two distinct vuln matches.
func dedupPatternsCbargWins(patterns []string) []string {
	hasCbarg := false
	for _, p := range patterns {
		if strings.Contains(p, "(cbarg)") {
			hasCbarg = true
			break
		}
	}
	if !hasCbarg {
		return patterns
	}
	// New backing array — corpus.Lookup returns shared Entry values whose
	// Patterns slice is owned by the corpus; writing through patterns[:0:…]
	// would silently mutate other vulns sharing the same id.
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if strings.Contains(p, "?") {
			continue
		}
		out = append(out, p)
	}
	return out
}

// RunPhase2 runs the heuristic-chain + bucket-split loop over the given vulns.
func (o *Orchestrator) RunPhase2(ctx context.Context, vulns []*internal.VulnRef) ([]*internal.Result, error) {
	if len(vulns) == 0 {
		return nil, nil
	}
	if len(o.Heuristics) == 0 {
		return nil, errors.New("scan: Orchestrator.Heuristics is empty")
	}

	queue := []Bucket{{
		Heuristic: o.Heuristics[0],
		Vulns:     vulns,
		Timeout:   o.Timeouts.AllVulnRuns,
	}}
	var out []*internal.Result

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b := queue[0]
		queue = queue[1:]

		results, err := o.RunOneBucket(ctx, b)
		if err == nil {
			out = append(out, results...)
			continue
		}

		// Don't bother splitting if the parent ctx is already done —
		// the next iteration's ctx.Err() check would catch it anyway,
		// but we'd waste a Split + tempdir setup first.
		if ctx.Err() == nil && isBucketTimeout(err) && b.Heuristic.SplitInBuckets() && len(b.Vulns) > 1 {
			left, right := b.Split(o.Timeouts.BucketedRuns)
			queue = append(queue, left, right)
			continue
		}
		next := nextHeuristic(o.Heuristics, b.Heuristic)
		if next != nil {
			queue = append(queue, Bucket{
				Heuristic: next,
				Vulns:     b.Vulns,
				Timeout:   b.Timeout,
			})
			continue
		}
		// Exhausted all options — emit skipped results.
		for _, v := range b.Vulns {
			out = append(out, &internal.Result{
				Ref:        v,
				OSVID:      v.OSVID,
				Skipped:    true,
				SkipReason: fmt.Sprintf("all heuristics exhausted; last error: %v", err),
			})
		}
	}
	// Post-loop ctx check: if the very last bucket emitted Skipped results
	// under a cancelled context (the in-loop check only fires at the TOP
	// of an iteration), the cancellation would otherwise ship as a
	// normal-completion result set. Propagate it instead.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// isBucketTimeout classifies whether `err` should drive bucket-splitting.
// Only the explicit ErrBucketTimeout sentinel and ctx.DeadlineExceeded count;
// generic killed-by-signal errors (OOM-killer, manual SIGKILL) advance the
// heuristic chain instead — splitting won't help if the next attempt also
// gets OOM-killed for the same memory pressure reason.
func isBucketTimeout(err error) bool {
	return errors.Is(err, ErrBucketTimeout) || errors.Is(err, context.DeadlineExceeded)
}

// nextHeuristic returns the heuristic after `cur` in `hs`, or nil.
func nextHeuristic(hs []Heuristic, cur Heuristic) Heuristic {
	for i, h := range hs {
		if h.Name() == cur.Name() && i+1 < len(hs) {
			return hs[i+1]
		}
	}
	return nil
}
