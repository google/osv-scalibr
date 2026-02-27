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

package paypal_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/paypal"
	"github.com/google/osv-scalibr/veles/velestest"
)

var (
	// Example valid PayPal Client ID (starts with "A", exactly 80 alphanumeric chars).
	detectorClientID = "A" + strings.Repeat("aBcDeFgHiJ", 7) + "aBcDeFgHi"
	// Example valid PayPal Client Secret (starts with "E", exactly 80 alphanumeric chars).
	detectorClientSecret = "E" + strings.Repeat("KlMnOpQrSt", 7) + "KlMnOpQrS"
)

func TestMain(m *testing.M) {
	// Validate lengths are correct.
	if len(detectorClientID) != 80 {
		panic("detectorClientID should be 80 chars")
	}
	if len(detectorClientSecret) != 80 {
		panic("detectorClientSecret should be 80 chars")
	}
	os.Exit(m.Run())
}

func TestClientIDDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		paypal.NewClientIDDetector(),
		detectorClientID,
		paypal.ClientID{Key: detectorClientID},
		velestest.WithPad('.'),
	)
}

func TestClientSecretDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		paypal.NewClientSecretDetector(),
		detectorClientSecret,
		paypal.ClientSecret{Key: detectorClientSecret},
		velestest.WithPad('.'),
	)
}

// TestClientIDDetector_truePositives tests Client ID detection.
func TestClientIDDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{paypal.NewClientIDDetector()},
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
		input: detectorClientID,
		want: []veles.Secret{
			paypal.ClientID{Key: detectorClientID},
		},
	}, {
		name:  "match at end of string",
		input: `PAYPAL_CLIENT_ID=` + detectorClientID,
		want: []veles.Secret{
			paypal.ClientID{Key: detectorClientID},
		},
	}, {
		name:  "match in quotes",
		input: `client_id="` + detectorClientID + `"`,
		want: []veles.Secret{
			paypal.ClientID{Key: detectorClientID},
		},
	}, {
		name:  "multiple matches",
		input: detectorClientID + "\n" + detectorClientID,
		want: []veles.Secret{
			paypal.ClientID{Key: detectorClientID},
			paypal.ClientID{Key: detectorClientID},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf("config:\n  paypal_client_id: %s\n",
			detectorClientID),
		want: []veles.Secret{
			paypal.ClientID{Key: detectorClientID},
		},
	}, {
		name:  "env_var_format",
		input: `export PAYPAL_CLIENT_ID="` + detectorClientID + `"`,
		want: []veles.Secret{
			paypal.ClientID{Key: detectorClientID},
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

// TestClientIDDetector_trueNegatives tests Client ID false negatives.
func TestClientIDDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{paypal.NewClientIDDetector()},
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
		name:  "too short should not match",
		input: "A" + strings.Repeat("a", 30),
	}, {
		name:  "does not start with A",
		input: "B" + strings.Repeat("a", 79),
	}, {
		name:  "contains invalid characters",
		input: "A" + strings.Repeat("!", 79),
	}, {
		name:  "starts with lowercase a",
		input: "a" + strings.Repeat("B", 79),
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

// TestClientSecretDetector_truePositives tests Client Secret detection.
func TestClientSecretDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{paypal.NewClientSecretDetector()},
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
		input: detectorClientSecret,
		want: []veles.Secret{
			paypal.ClientSecret{Key: detectorClientSecret},
		},
	}, {
		name:  "match at end of string",
		input: `PAYPAL_CLIENT_SECRET=` + detectorClientSecret,
		want: []veles.Secret{
			paypal.ClientSecret{Key: detectorClientSecret},
		},
	}, {
		name:  "match in quotes",
		input: `secret="` + detectorClientSecret + `"`,
		want: []veles.Secret{
			paypal.ClientSecret{Key: detectorClientSecret},
		},
	}, {
		name:  "multiple matches",
		input: detectorClientSecret + " " + detectorClientSecret,
		want: []veles.Secret{
			paypal.ClientSecret{Key: detectorClientSecret},
			paypal.ClientSecret{Key: detectorClientSecret},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf("config:\n  paypal_secret: %s\n",
			detectorClientSecret),
		want: []veles.Secret{
			paypal.ClientSecret{Key: detectorClientSecret},
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

// TestClientSecretDetector_trueNegatives tests Client Secret false negatives.
func TestClientSecretDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{paypal.NewClientSecretDetector()},
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
		name:  "too short should not match",
		input: "E" + strings.Repeat("a", 30),
	}, {
		name:  "does not start with E",
		input: "F" + strings.Repeat("a", 79),
	}, {
		name:  "contains invalid characters",
		input: "E" + strings.Repeat("!", 79),
	}, {
		name:  "starts with lowercase e",
		input: "e" + strings.Repeat("B", 79),
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
