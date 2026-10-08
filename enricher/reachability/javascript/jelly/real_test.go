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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

// These snapshot tests guard against accidental flag-order or flag-spelling
// regressions in the inlined builder chains in real.go::RunImportOnly and
// real.go::RunFullScan. Mirror those chains exactly; if you add a flag at
// the call site, add it here too in the same position.

func TestImportOnlyFlags_Snapshot(t *testing.T) {
	got := newFlags().
		BaseDir("/proj").
		Timeout(90*time.Second).
		ModulesOnly().
		Scope([]string{"lodash", "react"}).
		ExcludeEntries([]string{"node_modules/.jelly/**"}).
		ReachableFile("/tmp/reach.json").
		MaxFileSize(524288).
		IgnoreUnresolved().
		EntryPointsOrDefault("/proj", nil).
		Build()
	want := []string{
		"-b", "/proj",
		"-i", "90",
		"--modules-only",
		"--include-packages", "lodash", "react",
		"--exclude-entries", "node_modules/.jelly/**",
		"--reachable-file", "/tmp/reach.json",
		"--max-file-size", "524288",
		"--ignore-unresolved",
		"/proj",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("import-only flags mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestImportOnlyFlags_NoIncludeUsesIgnoreDeps(t *testing.T) {
	got := newFlags().
		BaseDir("/proj").
		Timeout(30*time.Second).
		ModulesOnly().
		Scope(nil).
		ReachableFile("/tmp/reach.json").
		IgnoreUnresolved().
		EntryPointsOrDefault("/proj", nil).
		Build()
	if !slices.Contains(got, "--ignore-dependencies") {
		t.Errorf("expected --ignore-dependencies in %q", got)
	}
	if slices.Contains(got, "--include-packages") {
		t.Errorf("unexpected --include-packages in %q", got)
	}
}

func TestFullScanFlags_Snapshot(t *testing.T) {
	got := newFlags().
		BaseDir("/proj").
		Timeout(300*time.Second).
		Vulnerabilities("/tmp/v.json").
		VulnerabilitiesFull().
		Scope([]string{"lodash"}).
		ExcludeEntries([]string{"test/**"}).
		MatchesFile("/tmp/m.json").
		DiagnosticsJSON("/tmp/d.json").
		MaxIndirections(5).
		Approx(true).
		MaxFileSize(524288).
		IgnoreUnresolved().
		EntryPointsOrDefault("/proj", nil).
		Build()
	want := []string{
		"-b", "/proj",
		"-i", "300",
		"-v", "/tmp/v.json",
		"--vulnerabilities-full",
		"--include-packages", "lodash",
		"--exclude-entries", "test/**",
		"--matches-file", "/tmp/m.json",
		"--diagnostics-json", "/tmp/d.json",
		"--max-indirections", "5",
		"--approx",
		"--max-file-size", "524288",
		"--ignore-unresolved",
		"/proj",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("full-scan flags mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestWithNodeOptions_DefaultsWhenAbsent(t *testing.T) {
	got := withNodeOptions([]string{"FOO=bar"}, "")
	if !slices.Contains(got, "NODE_OPTIONS="+defaultNodeOptions) {
		t.Errorf("default NODE_OPTIONS missing from %q", got)
	}
}

func TestWithNodeOptions_DefaultsWinUnderLastWins(t *testing.T) {
	// Node parses NODE_OPTIONS left-to-right and last-wins for repeated
	// flags. The analyzer's defaults MUST come after any operator value so
	// e.g. an operator's --max-old-space-size=512 doesn't silently shrink
	// jelly's heap below the OOM threshold the defaults exist to prevent.
	in := []string{"NODE_OPTIONS=--max-old-space-size=512 --inspect", "FOO=bar"}
	got := withNodeOptions(in, "")
	want := "NODE_OPTIONS=--max-old-space-size=512 --inspect " + defaultNodeOptions
	if !slices.Contains(got, want) {
		t.Errorf("combined NODE_OPTIONS wrong order: got %q, want entry %q", got, want)
	}
}

func ctxBackground(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

func TestParseNodeVersion(t *testing.T) {
	cases := []struct {
		in    string
		major int
		ok    bool
	}{
		{"v22.11.0\n", 22, true},
		{"v23.0.0", 23, true},
		{"v21.7.3", 21, true},
		{"v0.10.0", 0, false}, // major 0 rejected — not a real Node version
		{"not a version", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		gotMajor, gotOK := parseNodeMajor(c.in)
		if gotMajor != c.major || gotOK != c.ok {
			t.Errorf("parseNodeMajor(%q) = (%d, %v), want (%d, %v)",
				c.in, gotMajor, gotOK, c.major, c.ok)
		}
	}
}

func TestRealClient_Available_HappyIfJellyAndNode22(t *testing.T) {
	if _, err := exec.LookPath("jelly"); err != nil {
		t.Skip("jelly not on PATH; positive case covered by integration tests")
	}
	c := &realClient{}
	_ = c.Available(ctxBackground(t))
	// No assertion: just checking it doesn't panic.
}

func TestRealClient_Available_FalseWhenJellyAbsent(t *testing.T) {
	c := &realClient{jellyLookupPath: "/definitely/not/on/path/jelly"}
	if got := c.Available(ctxBackground(t)); got {
		t.Errorf("Available() = true when jelly binary absent")
	}
}

func TestParseScanResult(t *testing.T) {
	dir := t.TempDir()
	matchesPath := filepath.Join(dir, "m.json")
	diagPath := filepath.Join(dir, "d.json")

	matchesJSON := `{"GHSA-x":["app.js:12:1:12:27"],"GHSA-y":[]}`
	diagJSON := `{"analyzerRounds":4,"aborted":false,"timeout":false}`
	if err := os.WriteFile(matchesPath, []byte(matchesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(diagPath, []byte(diagJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readScanResult(matchesPath, diagPath, false)
	if err != nil {
		t.Fatalf("readScanResult: %v", err)
	}
	if len(got.Matches["GHSA-x"]) != 1 {
		t.Errorf("GHSA-x matches: got %v", got.Matches["GHSA-x"])
	}
	if _, ok := got.Matches["GHSA-y"]; !ok {
		t.Errorf("GHSA-y key missing; absent-but-key-present is the encoding for 'analyzed, no matches'")
	}
	if got.Diagnostics.AnalyzerRounds != 4 {
		t.Errorf("AnalyzerRounds: got %d, want 4", got.Diagnostics.AnalyzerRounds)
	}
	if got.LowConfidence {
		t.Errorf("LowConfidence should be false with 4 rounds")
	}
	if got.TimedOut {
		t.Errorf("TimedOut should be false")
	}
}

func TestParseScanResult_LowConfidence(t *testing.T) {
	dir := t.TempDir()
	mp := filepath.Join(dir, "m.json")
	dp := filepath.Join(dir, "d.json")
	_ = os.WriteFile(mp, []byte(`{}`), 0o600)
	_ = os.WriteFile(dp, []byte(`{"analyzerRounds":1,"timeout":true}`), 0o600)

	got, err := readScanResult(mp, dp, true /* subprocessTimedOut */)
	if err != nil {
		t.Fatalf("readScanResult: %v", err)
	}
	if !got.LowConfidence {
		t.Error("LowConfidence should be true when analyzerRounds<2 and terminatedEarly")
	}
	if !got.TimedOut {
		t.Error("TimedOut should be true")
	}
}

func TestDiagnosticsJSONRoundtrip(t *testing.T) {
	d := Diagnostics{AnalyzerRounds: 3, Aborted: true}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Diagnostics
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != d {
		t.Errorf("roundtrip mismatch: %v vs %v", back, d)
	}
}
