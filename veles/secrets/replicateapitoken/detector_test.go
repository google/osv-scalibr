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

package replicateapitoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/replicateapitoken"
	"github.com/google/osv-scalibr/veles/velestest"
)

// testKey is a syntactically valid (but fake) Replicate API token:
// `r8_` followed by 37 characters from the set [A-Za-z0-9_-].
const testKey = `r8_0123456789abcdefghijklmnopqrstuvwxyzA`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		replicateapitoken.NewDetector(),
		testKey,
		replicateapitoken.ReplicateAPIToken{Key: testKey},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Replicate API token/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{replicateapitoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testKey,
		want: []veles.Secret{
			replicateapitoken.ReplicateAPIToken{Key: testKey},
		},
	}, {
		name:  "match at end of string",
		input: `REPLICATE_API_TOKEN=` + testKey,
		want: []veles.Secret{
			replicateapitoken.ReplicateAPIToken{Key: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `REPLICATE_API_TOKEN="` + testKey + `"`,
		want: []veles.Secret{
			replicateapitoken.ReplicateAPIToken{Key: testKey},
		},
	}, {
		name:  "token containing dash and underscore",
		input: `r8_abcdefghij-klmnopqrst_uvwxyz012345678`,
		want: []veles.Secret{
			replicateapitoken.ReplicateAPIToken{Key: `r8_abcdefghij-klmnopqrst_uvwxyz012345678`},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			replicateapitoken.ReplicateAPIToken{Key: testKey},
			replicateapitoken.ReplicateAPIToken{Key: testKey},
			replicateapitoken.ReplicateAPIToken{Key: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "1\n",
		want: []veles.Secret{
			replicateapitoken.ReplicateAPIToken{Key: testKey},
			replicateapitoken.ReplicateAPIToken{Key: testKey[:len(testKey)-1] + "1"},
		},
	}, {
		name: "larger_input_containing_token",
		input: fmt.Sprintf(`
:test_token: r8_test
:replicate_api_token: %s
		`, testKey),
		want: []veles.Secret{
			replicateapitoken.ReplicateAPIToken{Key: testKey},
		},
	}, {
		name:  "potential match longer than max token length",
		input: testKey + `extra`,
		want: []veles.Secret{
			replicateapitoken.ReplicateAPIToken{Key: testKey},
		},
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Replicate API token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{replicateapitoken.NewDetector()})
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
		name:  "short token should not match",
		input: testKey[:len(testKey)-1],
	}, {
		name:  "invalid character in token should not match",
		input: `r8_0123456789abcdefghijklmnopqrstuvwxyz.`,
	}, {
		name:  "incorrect prefix should not match",
		input: `R8_0123456789abcdefghijklmnopqrstuvwxyzA`,
	}, {
		name:  "prefix missing underscore should not match",
		input: `r80123456789abcdefghijklmnopqrstuvwxyzAB`,
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
