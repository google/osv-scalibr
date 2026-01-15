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

package postmanapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/postmanapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	// Example valid Postman API and Collection tokens.
	detectorPMAK = "PMAK-68b96bd4ae8d2b0001db8a86-192b1cb49020c70a4d0c814ab71de822d7"
	detectorPMAT = "PMAT-01K4A58P2HS2Q43TXHSXFRDBZX"
)

func TestAPIKeyDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		postmanapikey.NewAPIKeyDetector(),
		detectorPMAK,
		postmanapikey.PostmanAPIKey{Key: detectorPMAK},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

func TestCollectionTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		postmanapikey.NewCollectionTokenDetector(),
		detectorPMAT,
		postmanapikey.PostmanCollectionToken{Key: detectorPMAT},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

// TestAPIKeyDetector_truePositives tests PMAK detection.
func TestAPIKeyDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{postmanapikey.NewAPIKeyDetector()},
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
		input: detectorPMAK,
		want: []veles.Secret{
			postmanapikey.PostmanAPIKey{Key: detectorPMAK},
		},
	}, {
		name:  "match at end of string",
		input: `POSTMAN_KEY=` + detectorPMAK,
		want: []veles.Secret{
			postmanapikey.PostmanAPIKey{Key: detectorPMAK},
		},
	}, {
		name:  "match in quotes",
		input: `key="` + detectorPMAK + `"`,
		want: []veles.Secret{
			postmanapikey.PostmanAPIKey{Key: detectorPMAK},
		},
	}, {
		name:  "multiple matches",
		input: detectorPMAK + "\n" + detectorPMAK,
		want: []veles.Secret{
			postmanapikey.PostmanAPIKey{Key: detectorPMAK},
			postmanapikey.PostmanAPIKey{Key: detectorPMAK},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf("config:\n  api_key: %s\n",
			detectorPMAK),
		want: []veles.Secret{
			postmanapikey.PostmanAPIKey{Key: detectorPMAK},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorPMAK + "EXTRA",
		want: []veles.Secret{
			postmanapikey.PostmanAPIKey{Key: detectorPMAK},
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

// TestAPIKeyDetector_trueNegatives tests PMAK false negatives.
func TestAPIKeyDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{postmanapikey.NewAPIKeyDetector()},
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
		input: detectorPMAK[:len(detectorPMAK)-5],
	}, {
		name: "invalid_character_in_key_should_not_match",
		input: "PMAK-" + strings.ReplaceAll(
			detectorPMAK[5:], "a", "!",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "XMAK-" + detectorPMAK[5:],
	}, {
		name:  "prefix missing dash should not match",
		input: "PMAK" + detectorPMAK[5:], // removes the dash
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

// TestCollectionTokenDetector_truePositives tests PMAT detection.
func TestCollectionTokenDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{postmanapikey.NewCollectionTokenDetector()},
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
		input: detectorPMAT,
		want: []veles.Secret{
			postmanapikey.PostmanCollectionToken{Key: detectorPMAT},
		},
	}, {
		name:  "match at end of string",
		input: `PMAT_KEY=` + detectorPMAT,
		want: []veles.Secret{
			postmanapikey.PostmanCollectionToken{Key: detectorPMAT},
		},
	}, {
		name:  "match in quotes",
		input: `secret="` + detectorPMAT + `"`,
		want: []veles.Secret{
			postmanapikey.PostmanCollectionToken{Key: detectorPMAT},
		},
	}, {
		name:  "multiple matches",
		input: detectorPMAT + " " + detectorPMAT,
		want: []veles.Secret{
			postmanapikey.PostmanCollectionToken{Key: detectorPMAT},
			postmanapikey.PostmanCollectionToken{Key: detectorPMAT},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf("token:\n  value: %s\n",
			detectorPMAT),
		want: []veles.Secret{
			postmanapikey.PostmanCollectionToken{Key: detectorPMAT},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorPMAT + "EXTRA",
		want: []veles.Secret{
			postmanapikey.PostmanCollectionToken{Key: detectorPMAT},
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

// TestCollectionTokenDetector_trueNegatives tests PMAT false negatives.
func TestCollectionTokenDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{postmanapikey.NewCollectionTokenDetector()},
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
		input: detectorPMAT[:len(detectorPMAT)-2],
	}, {
		name: "invalid_character_in_key_should_not_match",
		input: "PMAT-" + strings.ReplaceAll(
			detectorPMAT[5:], "A", "#",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "PMAX-" + detectorPMAT[5:],
	}, {
		name:  "prefix missing dash should not match",
		input: "PMAT" + detectorPMAT[5:], // removes the dash
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
