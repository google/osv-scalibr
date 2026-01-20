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

package denopat_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/denopat"
)

const testKeyDdp = `ddp_qz538MNyqwfETb1ikqeqHiqA9Aa9Pv22yzmw`

const testKeyDdo = `ddo_qz538MNyqwfETb1ikqeqHiqA9Aa9Pv22yzmw`

// TestDetector_truePositives tests for cases where we know the Detectors
// will find Deno PAT/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		denopat.NewUserTokenDetector(),
		denopat.NewOrgTokenDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "simple matching string with ddp_ prefix",
			input: testKeyDdp,
			want: []veles.Secret{
				denopat.DenoUserPAT{Pat: testKeyDdp},
			},
		},
		{
			name:  "simple matching string with ddo_ prefix",
			input: testKeyDdo,
			want: []veles.Secret{
				denopat.DenoOrgPAT{Pat: testKeyDdo},
			},
		},
		{
			name:  "match in middle of string",
			input: `DENO_PAT="` + testKeyDdp + `"`,
			want: []veles.Secret{
				denopat.DenoUserPAT{Pat: testKeyDdp},
			},
		},
		{
			name:  "multiple matches",
			input: testKeyDdp + testKeyDdo + testKeyDdp,
			// Note: Results are grouped by detector type (all user tokens first, then all org tokens)
			// since the two detectors run independently
			want: []veles.Secret{
				denopat.DenoUserPAT{Pat: testKeyDdp},
				denopat.DenoUserPAT{Pat: testKeyDdp},
				denopat.DenoOrgPAT{Pat: testKeyDdo},
			},
		},
		{
			name:  "multiple distinct matches with different prefixes",
			input: testKeyDdp + "\n" + testKeyDdo,
			want: []veles.Secret{
				denopat.DenoUserPAT{Pat: testKeyDdp},
				denopat.DenoOrgPAT{Pat: testKeyDdo},
			},
		},
		{
			name: "larger input containing key",
			input: fmt.Sprintf(`
		:test_api_key: pat-test
		:deno_pat: %s
				`, testKeyDdp),
			want: []veles.Secret{
				denopat.DenoUserPAT{Pat: testKeyDdp},
			},
		},
		{
			name:  "potential match longer than max key length",
			input: testKeyDdp + `extra`,
			want: []veles.Secret{
				denopat.DenoUserPAT{Pat: testKeyDdp},
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

// TestDetector_trueNegatives tests for cases where we know the Detectors
// will not find a Deno PAT.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		denopat.NewUserTokenDetector(),
		denopat.NewOrgTokenDetector(),
	})
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
		input: testKeyDdp[:len(testKeyDdp)-1],
	}, {
		name:  "invalid character in key should not match",
		input: testKeyDdp[:len(testKeyDdp)-1] + "!",
	}, {
		name:  "incorrect prefix should not match",
		input: "aaa_" + testKeyDdp[4:],
	}, {
		name:  "prefix missing dash should not match",
		input: testKeyDdp[4:],
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
