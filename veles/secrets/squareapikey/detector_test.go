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

package squareapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	squareapikey "github.com/google/osv-scalibr/veles/secrets/squareapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	// Example valid Square API and OAuth tokens.
	detectorPersonalAccessToken    = "EAAAlwuZiieL54OUmRp1q-7VFVcBa9QICgMkWOv8qAFsiSZdwyy6kP4xRduxAV1T"
	detectorOAuthApplicationSecret = "sq0csp-aebm-dWBi74tX5f-LQQ-pC5x3WtHg7jVajqTijTM0xc"
)

func TestPersonalAccessTokenDetector_Acceptance(t *testing.T) {
	d := squareapikey.NewPersonalAccessTokenDetector()

	velestest.AcceptDetector(
		t,
		d,
		detectorPersonalAccessToken,
		squareapikey.SquarePersonalAccessToken{
			Key: detectorPersonalAccessToken,
		},
	)
}

func TestOAuthApplicationSecretDetector_Acceptance(t *testing.T) {
	d := squareapikey.NewOAuthApplicationSecretDetector()

	velestest.AcceptDetector(
		t,
		d,
		detectorOAuthApplicationSecret,
		squareapikey.SquareOAuthApplicationSecret{
			Key: detectorOAuthApplicationSecret,
		},
	)
}


// TestPersonalAccessTokenDetector_truePositives tests Personal Access Token detection.
func TestPersonalAccessTokenDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{squareapikey.NewPersonalAccessTokenDetector()},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: detectorPersonalAccessToken,
		want: []veles.Secret{
			squareapikey.SquarePersonalAccessToken{Key: detectorPersonalAccessToken},
		},
	}, {
		name:  "match at end of string",
		input: `SQUARE_KEY=` + detectorPersonalAccessToken,
		want: []veles.Secret{
			squareapikey.SquarePersonalAccessToken{Key: detectorPersonalAccessToken},
		},
	}, {
		name:  "match in quotes",
		input: `key="` + detectorPersonalAccessToken + `"`,
		want: []veles.Secret{
			squareapikey.SquarePersonalAccessToken{Key: detectorPersonalAccessToken},
		},
	}, {
		name:  "multiple matches",
		input: detectorPersonalAccessToken + "\n" + detectorPersonalAccessToken,
		want: []veles.Secret{
			squareapikey.SquarePersonalAccessToken{Key: detectorPersonalAccessToken},
			squareapikey.SquarePersonalAccessToken{Key: detectorPersonalAccessToken},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf("config:\n  api_key: %s\n",
			detectorPersonalAccessToken),
		want: []veles.Secret{
			squareapikey.SquarePersonalAccessToken{Key: detectorPersonalAccessToken},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorPersonalAccessToken + "EXTRA",
		want: []veles.Secret{
			squareapikey.SquarePersonalAccessToken{Key: detectorPersonalAccessToken},
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}

// TestPersonalAccessTokenDetector_trueNegatives tests Personal Access Token false negatives.
func TestPersonalAccessTokenDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{squareapikey.NewPersonalAccessTokenDetector()},
	)
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
		input: detectorPersonalAccessToken[:len(detectorPersonalAccessToken)-5],
	}, {
		name: "invalid character in key should not match",
		input: "EAAA" + strings.ReplaceAll(
			detectorPersonalAccessToken[4:], "A", "!",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "XXXX" + detectorPersonalAccessToken[4:],
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}

// TestOAuthApplicationSecretDetector_truePositives tests OAuth Application Secret detection.
func TestOAuthApplicationSecretDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{squareapikey.NewOAuthApplicationSecretDetector()},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: detectorOAuthApplicationSecret,
		want: []veles.Secret{
			squareapikey.SquareOAuthApplicationSecret{Key: detectorOAuthApplicationSecret},
		},
	}, {
		name:  "match at end of string",
		input: `SQUARE_OAUTH_SECRET=` + detectorOAuthApplicationSecret,
		want: []veles.Secret{
			squareapikey.SquareOAuthApplicationSecret{Key: detectorOAuthApplicationSecret},
		},
	}, {
		name:  "match in quotes",
		input: `secret="` + detectorOAuthApplicationSecret + `"`,
		want: []veles.Secret{
			squareapikey.SquareOAuthApplicationSecret{Key: detectorOAuthApplicationSecret},
		},
	}, {
		name:  "multiple matches",
		input: detectorOAuthApplicationSecret + " " + detectorOAuthApplicationSecret,
		want: []veles.Secret{
			squareapikey.SquareOAuthApplicationSecret{Key: detectorOAuthApplicationSecret},
			squareapikey.SquareOAuthApplicationSecret{Key: detectorOAuthApplicationSecret},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf("token:\n  value: %s\n",
			detectorOAuthApplicationSecret),
		want: []veles.Secret{
			squareapikey.SquareOAuthApplicationSecret{Key: detectorOAuthApplicationSecret},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorOAuthApplicationSecret + "EXTRA",
		want: []veles.Secret{
			squareapikey.SquareOAuthApplicationSecret{Key: detectorOAuthApplicationSecret},
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}

// TestOAuthApplicationSecretDetector_trueNegatives tests OAuth Application Secret false negatives.
func TestOAuthApplicationSecretDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{squareapikey.NewOAuthApplicationSecretDetector()},
	)
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
		input: detectorOAuthApplicationSecret[:len(detectorOAuthApplicationSecret)-2],
	}, {
		name: "invalid character in key should not match",
		input: "sq0csp-" + strings.ReplaceAll(
			detectorOAuthApplicationSecret[7:], "a", "#",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "sq0csx-" + detectorOAuthApplicationSecret[7:],
	}, {
		name:  "prefix missing dash should not match",
		input: "sq0csp" + detectorOAuthApplicationSecret[7:], // removes the dash
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}
