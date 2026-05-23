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

package jelly

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// defaultNodeOptions raises Node's heap limits for jelly subprocesses. The
// `jelly` binary is a `#!/usr/bin/env node` script, so Node honors
// NODE_OPTIONS from the environment. Without the larger old-space cap real
// projects OOM on long fixpoint runs; the semi-space tweak reduces GC churn
// during heavy AST traversal.
const defaultNodeOptions = "--max-old-space-size=8192 --max-semi-space-size=128"

// realClient is the production implementation of Client.
type realClient struct {
	// jellyLookupPath lets tests override exec.LookPath("jelly").
	// Empty means "use exec.LookPath".
	jellyLookupPath string
	// nodeOptions overrides defaultNodeOptions in tests. Empty = use default.
	nodeOptions string
}

// NewRealClient returns a Client that shells out to the jelly binary on PATH.
func NewRealClient() Client { return &realClient{} }

// parseNodeMajor extracts the major-version integer from `node --version`
// output of the form "v22.11.0\n". A leading "v0" (e.g. very old Node)
// is rejected — the minimum supported real-world version is far above 0
// and accepting it would falsely succeed Available() if minNodeMajor were
// ever lowered.
func parseNodeMajor(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") {
		return 0, false
	}
	s = s[1:]
	major, _, ok2 := strings.Cut(s, ".")
	if !ok2 {
		return 0, false
	}
	n, err := strconv.Atoi(major)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// RunImportOnly runs the Phase 1 import-only pass.
func (c *realClient) RunImportOnly(ctx context.Context, a ImportOnlyArgs) (ImportResult, error) {
	args := newFlags().
		BaseDir(a.BaseDir).
		Timeout(a.Timeout).
		ModulesOnly().
		Scope(a.IncludePackages).
		ExcludeEntries(a.ExcludeEntries).
		ReachableFile(a.ReachableFileOut).
		MaxFileSize(a.MaxFileSize).
		IgnoreUnresolved().
		EntryPointsOrDefault(a.BaseDir, a.EntryPoints).
		Build()
	cause, runErr := c.runJelly(ctx, args, a.Timeout)
	if cause == terminationCanceled {
		// Parent ctx canceled / deadlined. runErr satisfies
		// errors.Is(err, context.Canceled / DeadlineExceeded), so
		// RunPhase1's errors.Is check propagates this upward.
		return ImportResult{}, runErr
	}
	// terminationTimedOut (our local wall-clock guard fired) and
	// terminationNormal+err (subprocess error with parent ctx alive) are
	// both ADVISORY failures: try to read the partial reachable-file —
	// anything jelly emitted before being killed is positive-evidence
	// (those packages ARE reachable) — and return it with the runErr.
	// runErr in the timeout case is the raw waitErr (e.g. *exec.ExitError
	// "signal: killed") and does NOT satisfy errors.Is(DeadlineExceeded),
	// so RunPhase1 won't conflate it with parent cancellation.
	doc := parseReachableFile(a.ReachableFileOut)
	if runErr != nil {
		return ImportResult{ReachablePackages: doc.Packages}, runErr
	}
	if doc.parseErr != nil {
		return ImportResult{}, doc.parseErr
	}
	return ImportResult{ReachablePackages: doc.Packages}, nil
}

// reachableFileDoc is the parsed form of jelly's --reachable-file output.
// parseErr captures a read/parse failure so callers can choose to either
// propagate it (clean success branch) or ignore it (salvage-partial branch).
type reachableFileDoc struct {
	Packages []ReachablePackage `json:"packages"`
	parseErr error
}

func parseReachableFile(path string) reachableFileDoc {
	raw, err := os.ReadFile(path)
	if err != nil {
		return reachableFileDoc{parseErr: fmt.Errorf("read reachable-file: %w", err)}
	}
	var doc reachableFileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return reachableFileDoc{parseErr: fmt.Errorf("parse reachable-file: %w", err)}
	}
	return doc
}

// RunFullScan runs the Phase 2 expensive scan. When the subprocess errors
// but produced partial output, the result is returned with TerminatedEarly
// set so the caller doesn't treat empty matches as authoritative.
// Parent-ctx cancellation is propagated as ctx.Canceled rather than being
// re-classified as a terminated-early diagnostic.
func (c *realClient) RunFullScan(ctx context.Context, a FullScanArgs) (ScanResult, error) {
	args := newFlags().
		BaseDir(a.BaseDir).
		Timeout(a.Timeout).
		Vulnerabilities(a.VulnerabilitiesFile).
		VulnerabilitiesFull().
		Scope(a.IncludePackages).
		ExcludeEntries(a.ExcludeEntries).
		MatchesFile(a.MatchesFile).
		DiagnosticsJSON(a.DiagnosticsFile).
		MaxIndirections(a.MaxIndirections).
		Approx(a.Approx).
		MaxFileSize(a.MaxFileSize).
		IgnoreUnresolved().
		EntryPointsOrDefault(a.BaseDir, a.EntryPoints).
		Build()
	cause, runErr := c.runJelly(ctx, args, a.Timeout)
	if cause == terminationCanceled {
		return ScanResult{}, runErr
	}
	result, readErr := readScanResult(a.MatchesFile, a.DiagnosticsFile, cause == terminationTimedOut)

	if runErr != nil {
		if readErr != nil {
			return ScanResult{}, fmt.Errorf("jelly failed (%w) and reading outputs failed (%w)", runErr, readErr)
		}
		// Subprocess errored but wrote some output. Two regimes:
		//   1. Matches non-empty AND analyzerRounds >= 2: the scan
		//      completed enough fixpoint rounds to be trustworthy — a
		//      non-zero exit is likely a teardown issue (unhandled
		//      promise, deinit failure) OR a kill that arrived after
		//      the main analysis was done. Keep the result and clear
		//      the early-termination flags that readScanResult set
		//      pessimistically from the kill signal; record runErr in
		//      TerminationError so operators can see what happened.
		//   2. Otherwise: mark TerminatedEarly so the scan layer
		//      advances heuristics rather than emitting "unreachable"
		//      on empty/partial matches.
		result.TerminationError = runErr
		if len(result.Matches) > 0 && result.Diagnostics.AnalyzerRounds >= 2 {
			result.TimedOut = false
			result.TerminatedEarly = false
			result.LowConfidence = false
		} else {
			result.TerminatedEarly = true
		}
		return result, nil
	}
	if readErr != nil {
		return ScanResult{}, readErr
	}
	return result, nil
}

// terminationCause classifies how runJelly's subprocess ended, so the
// caller can decide whether to bucket-split, advance heuristics, or
// propagate cancellation upstream.
//
// Zero value is terminationUnknown — chosen deliberately so a future
// code path that returns the unset value (e.g. `var cause terminationCause`
// then early-return without explicit assignment) fails loudly at the
// classify site rather than silently being treated as "clean exit".
type terminationCause int

const (
	terminationUnknown  terminationCause = iota // unset; never returned by runJelly
	terminationNormal                           // subprocess exited on its own
	terminationTimedOut                         // our wall-clock deadline fired
	terminationCanceled                         // parent ctx canceled
)

// withNodeOptions returns env with the analyzer's NODE_OPTIONS appended
// AFTER any operator-supplied NODE_OPTIONS. Node parses NODE_OPTIONS
// left-to-right with last-wins semantics for repeated flags, so placing
// the defaults at the end makes them effectively win for the keys we care
// about (e.g. --max-old-space-size) while still allowing operators to
// inject orthogonal flags (e.g. --inspect) via the shell.
func withNodeOptions(env []string, override string) []string {
	opts := override
	if opts == "" {
		opts = defaultNodeOptions
	}
	out := make([]string, 0, len(env)+1)
	merged := false
	for _, kv := range env {
		if existing, ok := strings.CutPrefix(kv, "NODE_OPTIONS="); ok {
			combined := opts
			if existing != "" {
				combined = existing + " " + opts
			}
			out = append(out, "NODE_OPTIONS="+combined)
			merged = true
			continue
		}
		out = append(out, kv)
	}
	if !merged {
		out = append(out, "NODE_OPTIONS="+opts)
	}
	return out
}

// readScanResult parses the matches-file and diagnostics-json.
func readScanResult(matchesPath, diagPath string, subprocessTimedOut bool) (ScanResult, error) {
	var res ScanResult
	if raw, err := os.ReadFile(matchesPath); err == nil {
		if err := json.Unmarshal(raw, &res.Matches); err != nil {
			return ScanResult{}, fmt.Errorf("parse matches-file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return ScanResult{}, fmt.Errorf("read matches-file: %w", err)
	}
	if raw, err := os.ReadFile(diagPath); err == nil {
		if err := json.Unmarshal(raw, &res.Diagnostics); err != nil {
			return ScanResult{}, fmt.Errorf("parse diagnostics-json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return ScanResult{}, fmt.Errorf("read diagnostics-json: %w", err)
	}
	res.TimedOut = subprocessTimedOut || res.Diagnostics.Timeout
	res.TerminatedEarly = res.TimedOut || res.Diagnostics.Aborted ||
		res.Diagnostics.LowMemory || res.Diagnostics.RangeError
	res.LowConfidence = res.Diagnostics.AnalyzerRounds < 2 && res.TerminatedEarly
	return res, nil
}
