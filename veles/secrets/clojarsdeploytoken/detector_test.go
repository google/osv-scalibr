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

package clojarsdeploytoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/clojarsdeploytoken"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testKey = `CLOJARS_deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		clojarsdeploytoken.NewDetector(),
		testKey,
		clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Clojars Deploy Token/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{clojarsdeploytoken.NewDetector()})
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
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "match at end of string",
		input: `CLOJARS_DEPLOY_TOKEN=` + testKey,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `CLOJARS_DEPLOY_TOKEN="` + testKey + `"`,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + " " + testKey + " " + testKey,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "a",
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey[:len(testKey)-1] + "a"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
	:test_deploy_token: CLOJARS_test
	:CLOJARS_DEPLOY_TOKEN: %s
			`, testKey),
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
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
// will not find a Clojars Deploy Token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{clojarsdeploytoken.NewDetector()})
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
		input: testKey[:len(testKey)-1],
	}, {
		name:  "uppercase hex should not match",
		input: `CLOJARS_DEADBEEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123`,
	}, {
		name:  "invalid character in key should not match",
		input: `CLOJARS_deadbeef0123456789abcdef01234567g9abcdef0123456789abcdef0123`,
	}, {
		name:  "incorrect prefix should not match",
		input: `CLOJARD_deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123`,
	}, {
		name:  "lowercase prefix should not match",
		input: `clojars_deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123`,
	}, {
		name:  "missing prefix should not match",
		input: `deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123`,
	}, {
		name:  "extra characters in key should not match",
		input: `CLOJARS_deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234`,
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
