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

package qwenpat_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/qwenpat"
)

const testQwenAPIKey = `sk-8jxqzgqkdv4xvpmhczrjq7k` // 32 characters long


// TestDetector_truePositives tests for cases where we know the Detector
// will find a Qwen PAT/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{qwenpat.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "simple matching string with qdp_ prefix",
			input: testQwenAPIKey,
			want: []veles.Secret{
				qwenpat.QwenPAT{Pat: testQwenAPIKey},
			},
		},
		{
			name:  "match in middle of string",
			input: `QWEN_PAT="` + testQwenAPIKey + `"`,
			want: []veles.Secret{
				qwenpat.QwenPAT{Pat: testQwenAPIKey},
			},
		},
		{
			name:  "multiple matches",
			input: testQwenAPIKey + testQwenAPIKey,
			want: []veles.Secret{
				qwenpat.QwenPAT{Pat: testQwenAPIKey},
				qwenpat.QwenPAT{Pat: testQwenAPIKey},
			},
		},
		{
			name: "larger input containing key",
			input: fmt.Sprintf(`
		:test_api_key: pat-test
		:qwen_pat: %s
				`, testQwenAPIKey),
			want: []veles.Secret{
				qwenpat.QwenPAT{Pat: testQwenAPIKey},
			},
		},
		{
			name:  "potential match longer than max key length",
			input: testQwenAPIKey + `extra`,
			want: []veles.Secret{
				qwenpat.QwenPAT{Pat: testQwenAPIKey},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			fmt.Printf("got = %+v\n", got)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Qwen PAT.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{qwenpat.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty input",
		input: "",
	}, {
		name:  "short key should not match",
		input: testQwenAPIKey[:len(testQwenAPIKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: testQwenAPIKey[:len(testQwenAPIKey)-1] + "!",
	}, {
		name:  "incorrect prefix should not match",
		input: "aaa_" + testQwenAPIKey[3:],
	}, {
		name:  "prefix missing dash should not match",
		input: testQwenAPIKey[3:],
	}}
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
