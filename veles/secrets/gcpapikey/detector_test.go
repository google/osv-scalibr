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

package gcpapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testKeyA = `AIzaSyAtestTESTt3s7te-_testtesttesttest`
	testKeyB = `AIzaSyBtestTESTt3s7te-_testtesttesttest`
	testKeyC = `AIzaSyCtestTESTt3s7te-_testtesttesttest`
	testKeyD = `AIzaSyDtestTESTt3s7te-_testtesttesttest`
	testKey  = testKeyA
)

func TestDetectorAcceptance(t *testing.T) {
	d := gcpapikey.NewDetector()
	cases := []struct {
		name string
		key  string
	}{
		{
			name: "prefix-A",
			key:  testKeyA,
		},
		{
			name: "prefix-B",
			key:  testKeyB,
		},
		{
			name: "prefix-C",
			key:  testKeyC,
		},
		{
			name: "prefix-D",
			key:  testKeyD,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			velestest.AcceptDetector(
				t,
				d,
				tc.key,
				gcpapikey.GCPAPIKey{Key: tc.key},
				velestest.WithBackToBack(),
				velestest.WithPad('a'),
			)
		})
	}
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a GCP API key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gcpapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "simple matching string with A prefix",
			input: testKeyA,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKeyA},
			},
		},
		{
			name:  "simple matching string with B prefix",
			input: testKeyB,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKeyB},
			},
		},
		{
			name:  "simple matching string with C prefix",
			input: testKeyC,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKeyC},
			},
		},
		{
			name:  "simple matching string with D prefix",
			input: testKeyD,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKeyD},
			},
		},
		{
			name:  "match at end of string",
			input: `API_KEY=` + testKey,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKey},
			},
		},
		{
			name:  "match in middle of string",
			input: `API_KEY="` + testKey + `"`,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKey},
			},
		},
		{
			name:  "multiple matches",
			input: testKey + testKey + testKey,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKey},
				gcpapikey.GCPAPIKey{Key: testKey},
				gcpapikey.GCPAPIKey{Key: testKey},
			},
		},
		{
			name:  "multiple distinct matches",
			input: testKey + "\n" + testKey[:len(testKey)-1] + "1\n",
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKey},
				gcpapikey.GCPAPIKey{Key: testKey[:len(testKey)-1] + "1"},
			},
		},
		{
			name: "larger_input_containing_key",
			input: fmt.Sprintf(`
CONFIG_FILE=config.txt
API_KEY=%s
CLOUD_PROJECT=my-project
		`, testKey),
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKey},
			},
		},
		{
			name:  "potential match longer than max key length",
			input: testKey + `test`,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: testKey},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a GCP API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gcpapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "wrong prefix",
			input: "AIzaSyEtestTESTt3s7te-_testtesttesttest",
		},
		{
			name:  "short key",
			input: testKey[:len(testKey)-1],
		},
		{
			name:  "incorrect casing of prefix",
			input: `aizaSyAtestTESTt3s7te-_testtesttesttest`,
		},
		{
			name:  "special character in key",
			input: `AIzaSyAtest.TESTt3s7te-_testtesttesttes`,
		},
		{
			name:  "special character in prefix",
			input: `AI.zaSyAtestTESTt3s7te-_testtesttesttes`,
		},
		{
			name:  "special character after prefix",
			input: `AIzaSyA.testTESTt3s7te-_testtesttesttes`,
		},
		{
			// See https://pkg.go.dev/regexp and
			// https://github.com/google/re2/wiki/syntax.
			name:  "overlapping matches not supported",
			input: `AIzaSyA` + testKey,
			want: []veles.Secret{
				gcpapikey.GCPAPIKey{Key: `AIzaSyA` + testKey[:len(testKey)-7]},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
