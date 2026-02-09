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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stripeapikeys_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/stripeapikeys"
	"github.com/google/osv-scalibr/veles/velestest"
)

var (
	// Example valid Stripe API and Webhook secrets.
	detectorSK    = "sk_live_" + strings.Repeat("a", 99)
	detectorRK    = "rk_live_" + strings.Repeat("a", 99)
	detectorWHSEC = "whsec_UOTBUgpYjyLswPFMxvzo4PyUxleOAiJd"
)

func TestSecretKeyDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		stripeapikeys.NewSecretKeyDetector(),
		detectorSK,
		stripeapikeys.StripeSecretKey{Key: detectorSK},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

func TestRestrictedKeyDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		stripeapikeys.NewRestrictedKeyDetector(),
		detectorRK,
		stripeapikeys.StripeRestrictedKey{Key: detectorRK},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

func TestWebhookSecretDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		stripeapikeys.NewWebhookSecretDetector(),
		detectorWHSEC,
		stripeapikeys.StripeWebhookSecret{Key: detectorWHSEC},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

// TestSecretKeyDetector_truePositives tests SK detection.
func TestSecretKeyDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{stripeapikeys.NewSecretKeyDetector()},
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
		input: detectorSK,
		want: []veles.Secret{
			stripeapikeys.StripeSecretKey{Key: detectorSK},
		},
	}, {
		name:  "match at end of string",
		input: `STRIPE_KEY=` + detectorSK,
		want: []veles.Secret{
			stripeapikeys.StripeSecretKey{Key: detectorSK},
		},
	}, {
		name:  "match in quotes",
		input: `key="` + detectorSK + `"`,
		want: []veles.Secret{
			stripeapikeys.StripeSecretKey{Key: detectorSK},
		},
	}, {
		name:  "multiple matches",
		input: detectorSK + "\n" + detectorSK,
		want: []veles.Secret{
			stripeapikeys.StripeSecretKey{Key: detectorSK},
			stripeapikeys.StripeSecretKey{Key: detectorSK},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf("config:\n  api_key: %s\n",
			detectorSK),
		want: []veles.Secret{
			stripeapikeys.StripeSecretKey{Key: detectorSK},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorSK + "Extra",
		want: []veles.Secret{
			stripeapikeys.StripeSecretKey{Key: detectorSK},
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

// TestSecretKeyDetector_trueNegatives tests SK false negatives.
func TestSecretKeyDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{stripeapikeys.NewSecretKeyDetector()},
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
		input: detectorSK[:len(detectorSK)-90],
	}, {
		name: "invalid_character_in_key_should_not_match",
		input: "sk_live_" + strings.ReplaceAll(
			detectorSK[8:], "a", "!",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "pk_live_" + detectorSK[8:],
	}, {
		name:  "prefix missing underscore should not match",
		input: "sk-live_" + detectorSK[8:], // removes the underscore
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

// TestRestrictedKeyDetector_truePositives tests RK detection.
func TestRestrictedKeyDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{stripeapikeys.NewRestrictedKeyDetector()},
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
		input: detectorRK,
		want: []veles.Secret{
			stripeapikeys.StripeRestrictedKey{Key: detectorRK},
		},
	}, {
		name:  "match at end of string",
		input: `STRIPE_RK=` + detectorRK,
		want: []veles.Secret{
			stripeapikeys.StripeRestrictedKey{Key: detectorRK},
		},
	}, {
		name:  "match in quotes",
		input: `secret="` + detectorRK + `"`,
		want: []veles.Secret{
			stripeapikeys.StripeRestrictedKey{Key: detectorRK},
		},
	}, {
		name:  "multiple matches",
		input: detectorRK + " " + detectorRK,
		want: []veles.Secret{
			stripeapikeys.StripeRestrictedKey{Key: detectorRK},
			stripeapikeys.StripeRestrictedKey{Key: detectorRK},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf("token:\n  value: %s\n",
			detectorRK),
		want: []veles.Secret{
			stripeapikeys.StripeRestrictedKey{Key: detectorRK},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorRK + "Extra",
		want: []veles.Secret{
			stripeapikeys.StripeRestrictedKey{Key: detectorRK},
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

// TestRestrictedKeyDetector_trueNegatives tests RK false negatives.
func TestRestrictedKeyDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{stripeapikeys.NewRestrictedKeyDetector()},
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
		input: detectorRK[:len(detectorRK)-90],
	}, {
		name: "invalid_character_in_key_should_not_match",
		input: "rk_live_" + strings.ReplaceAll(
			detectorRK[8:], "a", "#",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "sk_live_" + detectorRK[8:],
	}, {
		name:  "prefix missing underscore should not match",
		input: "rk-live_" + detectorRK[8:], // removes the underscore
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

// TestWebhookSecretDetector_truePositives tests WHSEC detection.
func TestWebhookSecretDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{stripeapikeys.NewWebhookSecretDetector()},
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
		input: detectorWHSEC,
		want: []veles.Secret{
			stripeapikeys.StripeWebhookSecret{Key: detectorWHSEC},
		},
	}, {
		name:  "match at end of string",
		input: `STRIPE_WHSEC=` + detectorWHSEC,
		want: []veles.Secret{
			stripeapikeys.StripeWebhookSecret{Key: detectorWHSEC},
		},
	}, {
		name:  "match in quotes",
		input: `secret="` + detectorWHSEC + `"`,
		want: []veles.Secret{
			stripeapikeys.StripeWebhookSecret{Key: detectorWHSEC},
		},
	}, {
		name:  "multiple matches",
		input: detectorWHSEC + " " + detectorWHSEC,
		want: []veles.Secret{
			stripeapikeys.StripeWebhookSecret{Key: detectorWHSEC},
			stripeapikeys.StripeWebhookSecret{Key: detectorWHSEC},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf("token:\n  value: %s\n",
			detectorWHSEC),
		want: []veles.Secret{
			stripeapikeys.StripeWebhookSecret{Key: detectorWHSEC},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorWHSEC + strings.Repeat("a", 500),
		want: []veles.Secret{
			stripeapikeys.StripeWebhookSecret{Key: detectorWHSEC},
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

// TestWebhookSecretDetector_trueNegatives tests WHSEC false negatives.
func TestWebhookSecretDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{stripeapikeys.NewWebhookSecretDetector()},
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
		input: detectorWHSEC[:len(detectorWHSEC)-2],
	}, {
		name: "invalid_character_in_key_should_not_match",
		input: "whsec_" + strings.ReplaceAll(
			detectorWHSEC[6:], "U", "#",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "whsec-" + detectorWHSEC[6:],
	}, {
		name:  "prefix missing underscore should not match",
		input: "whsec" + detectorWHSEC[6:], // removes the underscore
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
