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
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/corpus"
	"github.com/google/osv-scalibr/enricher/reachability/javascript/internal"
)

func TestWriteBucketVulns_NoDupesWhenSameOSVIDAppearsMultipleTimes(t *testing.T) {
	// Regression: writeBucketVulns used to call corp.Lookup once per
	// VulnRef, so when two refs shared an OSV id the same entries were
	// appended twice and serialized as N duplicate records in vulns.json.
	// Fix: each unique OSV id is looked up at most once.
	corpJSON := `[
	  {"osv":{"id":"GHSA-x"},"patterns":["call <a>.foo"]}
	]`
	corpDir := t.TempDir()
	corpPath := corpDir + "/corpus.json"
	if err := os.WriteFile(corpPath, []byte(corpJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := corpus.Load(corpPath)
	if err != nil {
		t.Fatal(err)
	}
	out := corpDir + "/vulns.json"
	// Two distinct VulnRefs with the same OSVID — one CVE matched against
	// two installed packages, the exact scenario the byRef refactor
	// supports.
	vulns := []*internal.VulnRef{
		{OSVID: "GHSA-x", PackageName: "a", PackageVersion: "1.0.0"},
		{OSVID: "GHSA-x", PackageName: "a", PackageVersion: "2.0.0"},
	}
	if err := writeBucketVulns(out, vulns, c); err != nil {
		t.Fatalf("writeBucketVulns: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// Decode as a generic []any and count entries — should be 1, not 2.
	var entries []any
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("want 1 entry in vulns.json, got %d (%s)", len(entries), body)
	}
}

func TestDedupPatternsCbargWins(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no cbarg: passthrough untouched",
			in:   []string{"call <x>.a", "call <x>.b?"},
			want: []string{"call <x>.a", "call <x>.b?"},
		},
		{
			name: "cbarg present: ? patterns dropped",
			in:   []string{"call <x>.a?", "call <x>.b(cbarg)"},
			want: []string{"call <x>.b(cbarg)"},
		},
		{
			name: "cbarg present: non-? patterns kept",
			in:   []string{"call <x>.plain", "call <x>.a?", "call <x>.b(cbarg)"},
			want: []string{"call <x>.plain", "call <x>.b(cbarg)"},
		},
		{
			name: "all cbarg: nothing dropped",
			in:   []string{"call <x>.a(cbarg)", "call <y>.b(cbarg)"},
			want: []string{"call <x>.a(cbarg)", "call <y>.b(cbarg)"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Snapshot the input so we can detect accidental mutation of the
			// caller's backing array — corpus shares Patterns slices across
			// holders, so any in-place edit would corrupt other vulns.
			snapshot := append([]string(nil), tc.in...)
			got := dedupPatternsCbargWins(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if !reflect.DeepEqual(tc.in, snapshot) {
				t.Errorf("input was mutated: now %q, was %q", tc.in, snapshot)
			}
		})
	}
}
