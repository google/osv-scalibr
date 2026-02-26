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

const testKey = `CLOJARS_cafe6346d9ef5c39890999e697f99dda6621dd03884705d341a198c6ce75`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		clojarsdeploytoken.NewDetector(),
		testKey,
		clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
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
		input: `CLOJARS_TOKEN=` + testKey,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `CLOJARS_TOKEN="` + testKey + `"`,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name: "multiple distinct matches",
		// Note: We modify the last char to 'a' which is valid hex
		input: testKey + "\n" + testKey[:len(testKey)-1] + "a",
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey[:len(testKey)-1] + "a"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:CLOJARS_TOKEN: %s
		`, testKey),
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `extra`,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name: "env",
		input: `
		HEROKU_API_KEY="HRKU_2025-01-01-preview-Placeholder"
		CLOJARS_USERNAME="clojars-placeholder-username"
		CLOJARS_TOKEN="CLOJARS_cafe6346d9ef5c39890999e697f99dda6621dd03884705d341a198c6ce75"
		# EMBEDDING_MODEL_NAME_OR_PATH="sentence-transformers/paraphrase-multilingual-mpnet-base-v2"
		`,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{
				Token:    testKey,
				Username: "clojars-placeholder-username",
			},
		},
	}, {
		name: "JSON formatted credentials",
		input: `{
			"username": "service_account",
			"password": "` + testKey + `"
		}`,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey, Username: "service_account"},
		},
	},
		{
			name:  "YAML formatted credentials with colon",
			input: "username: deploy_user\npassword: " + testKey,
			want: []veles.Secret{
				clojarsdeploytoken.ClojarsDeployToken{Token: testKey, Username: "deploy_user"},
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
		name: "invalid character in key should not match",
		// Replaced 'c' with 'Z' (non-hex)
		input: `CLOJARS_Zafe6346d9ef5c39890999e697f99dda6621dd03884705d341a198c6ce75`,
	}, {
		name: "uppercase hex characters should not match",
		// Replaced 'cafe' with 'CAFE' to test strict lowercase enforcement
		input: `CLOJARS_CAFE6346d9ef5c39890999e697f99dda6621dd03884705d341a198c6ce75`,
	}, {
		name:  "incorrect prefix should not match",
		input: `DLOJARS_cafe6346d9ef5c39890999e697f99dda6621dd03884705d341a198c6ce75`,
	}, {
		name:  "prefix missing underscore should not match",
		input: `CLOJARScafe6346d9ef5c39890999e697f99dda6621dd03884705d341a198c6ce75`,
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
