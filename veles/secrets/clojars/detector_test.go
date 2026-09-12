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

package clojars_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/clojars"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testDeployToken = `CLOJARS_0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdef`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		clojars.NewDetector(),
		testDeployToken,
		clojars.DeployToken{Token: testDeployToken},
	)
}

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{clojars.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	otherToken := testDeployToken[:len(testDeployToken)-1] + "0"
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testDeployToken,
		want: []veles.Secret{
			clojars.DeployToken{Token: testDeployToken},
		},
	}, {
		name:  "match at end of env assignment",
		input: `CLOJARS_DEPLOY_TOKEN=` + testDeployToken,
		want: []veles.Secret{
			clojars.DeployToken{Token: testDeployToken},
		},
	}, {
		name:  "match in quoted config value",
		input: `:deploy-token "` + testDeployToken + `"`,
		want: []veles.Secret{
			clojars.DeployToken{Token: testDeployToken},
		},
	}, {
		name:  "multiple distinct matches",
		input: testDeployToken + "\n" + otherToken,
		want: []veles.Secret{
			clojars.DeployToken{Token: testDeployToken},
			clojars.DeployToken{Token: otherToken},
		},
	}, {
		name: "larger input containing token",
		input: fmt.Sprintf(`
	:username "example"
	:password "%s"
		`, testDeployToken),
		want: []veles.Secret{
			clojars.DeployToken{Token: testDeployToken},
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

func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{clojars.NewDetector()})
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
		input: testDeployToken[:len(testDeployToken)-1],
	}, {
		name:  "long token should not match",
		input: testDeployToken + "0",
	}, {
		name:  "invalid hex character should not match",
		input: testDeployToken[:len(testDeployToken)-1] + "g",
	}, {
		name:  "incorrect prefix should not match",
		input: "CLOJURE_" + testDeployToken[len("CLOJARS_"):],
	}, {
		name:  "lowercase prefix should not match",
		input: strings.ToLower(testDeployToken[:len("CLOJARS_")]) + testDeployToken[len("CLOJARS_"):],
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
