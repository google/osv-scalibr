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

package scan_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/corpus"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/internal"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/jelly"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/scan"
)

func TestVulnPathOnly_PerVulnRefMapKeysSurviveSharedOSVID(t *testing.T) {
	// Regression: VulnPathOnly used to key VulnPathPackages by OSVID,
	// which collapsed two distinct VulnRefs sharing one CVE id into one
	// entry — the second iteration overwrote the first's paths. The fix
	// keys by VulnRef pointer so each ref's paths survive.
	vulnA := &internal.VulnRef{OSVID: "GHSA-shared", PackageName: "lodash"}
	vulnB := &internal.VulnRef{OSVID: "GHSA-shared", PackageName: "underscore"}
	h := scan.VulnPathOnly{
		VulnPathPackages: map[*internal.VulnRef][]string{
			vulnA: {"express", "router"},
			vulnB: {"next", "cache"},
		},
	}
	got := h.IncludePackages([]*internal.VulnRef{vulnA, vulnB})
	want := map[string]bool{"express": true, "router": true, "next": true, "cache": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v — shared-OSVID paths must not collapse", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected package %q", p)
		}
	}
}

func TestVulnPathOnly_OtherVulnsLeavesStayInScope(t *testing.T) {
	// Regression: VulnPathOnly used to exclude every package that was the
	// leaf of ANY vuln in the same bucket. When vuln A=lodash had a path
	// running app → express → qs → lodash AND vuln B=qs was in the same
	// bucket, qs was dropped from the include set, breaking jelly's
	// traversal to lodash → both vulns marked false-unreachable. Fix:
	// each vuln only excludes its OWN leaf.
	vulnA := &internal.VulnRef{OSVID: "GHSA-a", PackageName: "lodash"}
	vulnB := &internal.VulnRef{OSVID: "GHSA-b", PackageName: "qs"}
	h := scan.VulnPathOnly{
		VulnPathPackages: map[*internal.VulnRef][]string{
			vulnA: {"express", "qs"}, // path to A's leaf lodash
			vulnB: {"express"},       // path to B's leaf qs
		},
	}
	vulns := []*internal.VulnRef{vulnA, vulnB}
	got := h.IncludePackages(vulns)
	wantSet := map[string]bool{"express": true, "qs": true}
	if len(got) != len(wantSet) {
		t.Fatalf("got %v, want %v (qs MUST be present — it is not A's own leaf)", got, wantSet)
	}
	for _, p := range got {
		if !wantSet[p] {
			t.Errorf("unexpected package in include set: %q", p)
		}
	}
}

func TestVulnPathOnly_IncludePackages(t *testing.T) {
	vulnA := &internal.VulnRef{OSVID: "GHSA-a", PackageName: "leafvuln"}
	vulnB := &internal.VulnRef{OSVID: "GHSA-b", PackageName: "leafvuln"}
	h := scan.VulnPathOnly{
		VulnPathPackages: map[*internal.VulnRef][]string{
			vulnA: {"rootdep", "middle", "leafvuln"},
			vulnB: {"otherroot", "leafvuln"},
		},
	}
	vulns := []*internal.VulnRef{vulnA, vulnB}
	got := h.IncludePackages(vulns)
	// Leaf (leafvuln) is excluded from the include set; everything else is in.
	want := map[string]bool{"rootdep": true, "middle": true, "otherroot": true}
	if len(got) != len(want) {
		t.Fatalf("got %d packages, want %d: %v", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected package %q", p)
		}
	}
	if h.MaxIndirections() != 5 {
		t.Errorf("MaxIndirections = %d, want 5", h.MaxIndirections())
	}
	if !h.SplitInBuckets() {
		t.Errorf("VulnPathOnly must have SplitInBuckets = true")
	}
}

func TestIgnoreDeps(t *testing.T) {
	h := scan.IgnoreDeps{}
	got := h.IncludePackages(nil)
	if len(got) != 1 || got[0] != "__scalibr_sentinel_no_such_pkg__" {
		t.Errorf("IgnoreDeps.IncludePackages = %v, want sentinel", got)
	}
	if h.MaxIndirections() != 3 {
		t.Errorf("MaxIndirections = %d, want 3", h.MaxIndirections())
	}
	if h.SplitInBuckets() {
		t.Errorf("IgnoreDeps must have SplitInBuckets = false")
	}
}

func TestAccessPathReachable_PlainName(t *testing.T) {
	reachable := []jelly.ReachablePackage{{Name: "lodash"}, {Name: "react"}}
	if !scan.AccessPathReachable("call <lodash>.template", reachable) {
		t.Error("plain name in reachable set should match")
	}
	if scan.AccessPathReachable("call <missing>.x", reachable) {
		t.Error("plain name not in reachable set should miss")
	}
}

func TestAccessPathReachable_SubpathPrefix(t *testing.T) {
	reachable := []jelly.ReachablePackage{{Name: "react-server-dom-webpack"}}
	ap := "call <react-server-dom-webpack/server.edge>.decodeReply"
	if !scan.AccessPathReachable(ap, reachable) {
		t.Error("subpath-within-reachable-package should match")
	}
}

func TestAccessPathReachable_Glob(t *testing.T) {
	reachable := []jelly.ReachablePackage{{Name: "react-server-dom-webpack"}}
	ap := "call <react-server-dom-webpack/**>.decodeReply"
	if !scan.AccessPathReachable(ap, reachable) {
		t.Error("glob inside <> should match on prefix")
	}
}

func TestAccessPathReachable_AllTokensMustMatch(t *testing.T) {
	reachable := []jelly.ReachablePackage{{Name: "a"}}
	// Multiple <> tokens: all must match.
	if scan.AccessPathReachable("call <a>.foo.<missing>", reachable) {
		t.Error("if any <> token misses, pattern should be unreachable")
	}
}

func TestRunPhase1_PrunesUnreachable(t *testing.T) {
	c := &jelly.MockClient{
		AvailableResult: true,
		ImportResult: jelly.ImportResult{
			ReachablePackages: []jelly.ReachablePackage{{Name: "reachable"}},
		},
	}
	corp := mustCorpusFromJSON(t, `[
	  {"osv":{"id":"GHSA-reach"},"patterns":["call <reachable>.foo"]},
	  {"osv":{"id":"GHSA-unreach"},"patterns":["call <not-in-graph>.bar"]}
	]`)
	o := &scan.Orchestrator{
		Client: c, Corpus: corp, BaseDir: "/proj",
		Heuristics: []scan.Heuristic{scan.VulnPathOnly{}},
		Timeouts:   scan.DefaultTimeouts(),
	}
	vulns := []*internal.VulnRef{
		{OSVID: "GHSA-reach", AccessPathPatterns: []string{"call <reachable>.foo"}},
		{OSVID: "GHSA-unreach", AccessPathPatterns: []string{"call <not-in-graph>.bar"}},
	}
	remaining, pruned, err := o.RunPhase1(context.Background(), vulns)
	if err != nil {
		t.Fatalf("RunPhase1: %v", err)
	}
	if len(remaining) != 1 || remaining[0].OSVID != "GHSA-reach" {
		t.Errorf("remaining = %+v, want [GHSA-reach]", remaining)
	}
	if len(pruned) != 1 || pruned[0].OSVID != "GHSA-unreach" {
		t.Errorf("pruned = %+v, want [GHSA-unreach]", pruned)
	}
}

func mustCorpusFromJSON(t *testing.T, contents string) *corpus.Corpus {
	t.Helper()
	dir := t.TempDir()
	p := dir + "/corpus.json"
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := corpus.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRunOneBucket_Success(t *testing.T) {
	c := &jelly.MockClient{
		AvailableResult: true,
		FullScanResults: []jelly.ScanResult{
			{Matches: map[string][]string{"GHSA-matched": {"app.js:10:1:10:5"}}},
		},
	}
	corp := mustCorpusFromJSON(t, `[
	  {"osv":{"id":"GHSA-matched"},"patterns":["call <x>.y"]},
	  {"osv":{"id":"GHSA-nomatch"},"patterns":["call <x>.z"]}
	]`)
	o := &scan.Orchestrator{
		Client: c, Corpus: corp, BaseDir: "/proj",
		Heuristics: []scan.Heuristic{scan.VulnPathOnly{}},
		Timeouts:   scan.DefaultTimeouts(),
	}
	vulns := []*internal.VulnRef{
		{OSVID: "GHSA-matched"},
		{OSVID: "GHSA-nomatch"},
	}
	b := scan.Bucket{Heuristic: scan.VulnPathOnly{}, Vulns: vulns, Timeout: o.Timeouts.AllVulnRuns}
	results, err := o.RunOneBucket(context.Background(), b)
	if err != nil {
		t.Fatalf("RunOneBucket: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	m := map[string]*internal.Result{}
	for _, r := range results {
		m[r.OSVID] = r
	}
	if !m["GHSA-matched"].Reachable {
		t.Error("GHSA-matched should be Reachable=true")
	}
	if m["GHSA-nomatch"].Reachable {
		t.Error("GHSA-nomatch should be Reachable=false")
	}
}

func TestRunPhase2_SplitsOnTimeout(t *testing.T) {
	// First call: timeout. Next two calls (sub-buckets): success, empty matches.
	c := &jelly.MockClient{
		AvailableResult: true,
		FullScanResults: []jelly.ScanResult{
			{TimedOut: true},
			{Matches: map[string][]string{"GHSA-a": {}}},
			{Matches: map[string][]string{"GHSA-b": {}}},
		},
	}
	corp := mustCorpusFromJSON(t, `[
	  {"osv":{"id":"GHSA-a"},"patterns":["call <x>.a"]},
	  {"osv":{"id":"GHSA-b"},"patterns":["call <x>.b"]}
	]`)
	o := &scan.Orchestrator{
		Client: c, Corpus: corp, BaseDir: "/proj",
		Heuristics: []scan.Heuristic{scan.VulnPathOnly{}},
		Timeouts:   scan.TimeoutConfig{AllVulnRuns: 100, BucketedRuns: 50},
	}
	vulns := []*internal.VulnRef{
		{OSVID: "GHSA-a"},
		{OSVID: "GHSA-b"},
	}
	results, err := o.RunPhase2(context.Background(), vulns)
	if err != nil {
		t.Fatalf("RunPhase2: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Reachable {
			t.Errorf("%s: Reachable should be false", r.OSVID)
		}
	}
	if len(c.FullScanCalls) != 3 {
		t.Errorf("expected 3 jelly calls (1 timeout + 2 sub-buckets), got %d", len(c.FullScanCalls))
	}
}

func TestRunOneBucket_TerminatedEarlyWrapsTerminationError(t *testing.T) {
	// Regression: when RunFullScan returns TerminatedEarly=true with a
	// TerminationError (e.g. ENOENT from a missing jelly binary, OOM
	// kill signal), RunOneBucket must wrap that into the bucket error
	// so operators see the real cause in the "all heuristics exhausted"
	// diagnostic — not just a bare "jelly bucket terminated early".
	underlying := errors.New("simulated OOM kill: signal: killed")
	c := &jelly.MockClient{
		AvailableResult: true,
		FullScanResults: []jelly.ScanResult{
			{TerminatedEarly: true, TerminationError: underlying},
		},
	}
	corp := mustCorpusFromJSON(t, `[{"osv":{"id":"GHSA-a"},"patterns":["call <x>.a"]}]`)
	o := &scan.Orchestrator{
		Client: c, Corpus: corp, BaseDir: "/proj",
		Heuristics: []scan.Heuristic{scan.IgnoreDeps{}},
		Timeouts:   scan.DefaultTimeouts(),
	}
	b := scan.Bucket{Heuristic: scan.IgnoreDeps{}, Vulns: []*internal.VulnRef{{OSVID: "GHSA-a"}}, Timeout: o.Timeouts.AllVulnRuns}
	_, err := o.RunOneBucket(context.Background(), b)
	if !errors.Is(err, scan.ErrBucketTerminatedEarly) {
		t.Fatalf("error must satisfy errors.Is(ErrBucketTerminatedEarly); got %v", err)
	}
	if !errors.Is(err, underlying) {
		t.Errorf("error must wrap the underlying TerminationError for operator visibility; got %v", err)
	}
}

func TestRunOneBucket_TimedOutWrapsTerminationError(t *testing.T) {
	// Symmetric to TerminatedEarly: the TimedOut branch must ALSO wrap
	// the underlying TerminationError so operators see e.g. the
	// kill-signal info, not just "jelly bucket timed out".
	underlying := errors.New("simulated: signal: killed")
	c := &jelly.MockClient{
		AvailableResult: true,
		FullScanResults: []jelly.ScanResult{
			{TimedOut: true, TerminationError: underlying},
		},
	}
	corp := mustCorpusFromJSON(t, `[{"osv":{"id":"GHSA-a"},"patterns":["call <x>.a"]}]`)
	o := &scan.Orchestrator{
		Client: c, Corpus: corp, BaseDir: "/proj",
		Heuristics: []scan.Heuristic{scan.IgnoreDeps{}},
		Timeouts:   scan.DefaultTimeouts(),
	}
	b := scan.Bucket{Heuristic: scan.IgnoreDeps{}, Vulns: []*internal.VulnRef{{OSVID: "GHSA-a"}}, Timeout: o.Timeouts.AllVulnRuns}
	_, err := o.RunOneBucket(context.Background(), b)
	if !errors.Is(err, scan.ErrBucketTimeout) {
		t.Fatalf("error must satisfy errors.Is(ErrBucketTimeout); got %v", err)
	}
	if !errors.Is(err, underlying) {
		t.Errorf("error must wrap the underlying TerminationError; got %v", err)
	}
}

func TestRunPhase2_AdvancesHeuristicOnNonTimeoutError(t *testing.T) {
	c := &jelly.MockClient{
		AvailableResult: true,
		FullScanErrs:    []error{errors.New("synthetic fail"), nil},
		FullScanResults: []jelly.ScanResult{
			{},
			{Matches: map[string][]string{"GHSA-a": {}}},
		},
	}
	corp := mustCorpusFromJSON(t, `[{"osv":{"id":"GHSA-a"},"patterns":["call <x>.a"]}]`)
	o := &scan.Orchestrator{
		Client: c, Corpus: corp, BaseDir: "/proj",
		Heuristics: []scan.Heuristic{scan.VulnPathOnly{}, scan.IgnoreDeps{}},
		Timeouts:   scan.DefaultTimeouts(),
	}
	vulns := []*internal.VulnRef{{OSVID: "GHSA-a"}}
	results, err := o.RunPhase2(context.Background(), vulns)
	if err != nil {
		t.Fatalf("RunPhase2: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if len(c.FullScanCalls) != 2 {
		t.Errorf("expected 2 jelly calls (1 error + 1 fallback), got %d", len(c.FullScanCalls))
	}
}

func TestScan_FailedPackagesAreSkippedBeforePhase1(t *testing.T) {
	// The mock returns one match if Phase 2 were to run. A correct
	// implementation must skip the vuln entirely and never even hit Phase 1
	// for it, so the FullScan call count stays 0.
	c := &jelly.MockClient{
		AvailableResult: true,
		ImportResult:    jelly.ImportResult{ReachablePackages: nil},
		FullScanResults: []jelly.ScanResult{
			{Matches: map[string][]string{"GHSA-orphan": {"x.js:1:1:1:1"}}},
		},
	}
	corp := mustCorpusFromJSON(t, `[
	  {"osv":{"id":"GHSA-orphan"},"patterns":["call <missing-pkg>.x"]}
	]`)
	o := &scan.Orchestrator{
		Client: c, Corpus: corp, BaseDir: "/proj",
		Heuristics:     []scan.Heuristic{scan.IgnoreDeps{}},
		Timeouts:       scan.DefaultTimeouts(),
		FailedPackages: []internal.FailedPackage{{Name: "missing-pkg"}},
	}
	vulns := []*internal.VulnRef{
		{OSVID: "GHSA-orphan", PackageName: "missing-pkg"},
	}
	results, err := o.Scan(context.Background(), vulns)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(results), results)
	}
	r := results[0]
	if !r.Skipped {
		t.Errorf("vuln in failed package must be Skipped; got %+v", r)
	}
	if r.Reachable {
		t.Errorf("Skipped vuln must not be Reachable=true")
	}
	if len(c.FullScanCalls) != 0 {
		t.Errorf("vuln in failed package must bypass Phase 2; got %d calls", len(c.FullScanCalls))
	}
}

func TestScan_EndToEnd_Phase1PrunesThenPhase2(t *testing.T) {
	c := &jelly.MockClient{
		AvailableResult: true,
		ImportResult: jelly.ImportResult{
			ReachablePackages: []jelly.ReachablePackage{{Name: "reachable"}},
		},
		FullScanResults: []jelly.ScanResult{
			{Matches: map[string][]string{"GHSA-reach": {"app.js:1:1:1:2"}}},
		},
	}
	corp := mustCorpusFromJSON(t, `[
	  {"osv":{"id":"GHSA-reach"},"patterns":["call <reachable>.a"]},
	  {"osv":{"id":"GHSA-gone"},"patterns":["call <not-in-graph>.x"]}
	]`)
	o := &scan.Orchestrator{
		Client: c, Corpus: corp, BaseDir: "/proj",
		Heuristics: []scan.Heuristic{scan.VulnPathOnly{}},
		Timeouts:   scan.DefaultTimeouts(),
	}
	vulns := []*internal.VulnRef{
		{OSVID: "GHSA-reach", AccessPathPatterns: []string{"call <reachable>.a"}},
		{OSVID: "GHSA-gone", AccessPathPatterns: []string{"call <not-in-graph>.x"}},
	}
	results, err := o.Scan(context.Background(), vulns)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	m := map[string]*internal.Result{}
	for _, r := range results {
		m[r.OSVID] = r
	}
	if !m["GHSA-reach"].Reachable {
		t.Errorf("GHSA-reach: want Reachable=true (phase 2 matched)")
	}
	if m["GHSA-gone"].Reachable {
		t.Errorf("GHSA-gone: want Reachable=false (phase 1 pruned)")
	}
}
