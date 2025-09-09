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

package stripeapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	stripeapikey "github.com/google/osv-scalibr/veles/secrets/stripeapikey"
)

const webhookKey = `whsec_UOTBUgpYjyLswPFMxvzo4PyUxleOAiJd`

// TestWebhookDetector_truePositives tests for cases where we know the Detector
// will find a Stripe webhook secret.
func TestWebhookDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{stripeapikey.NewWebhookSecretDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: webhookKey,
		want: []veles.Secret{
			stripeapikey.StripeWebhookSecret{Key: webhookKey},
		},
	}, {
		name:  "match at end of string",
		input: `STRIPE_WEBHOOK_SECRET=` + webhookKey,
		want: []veles.Secret{
			stripeapikey.StripeWebhookSecret{Key: webhookKey},
		},
	}, {
		name:  "match in middle of string",
		input: `webhook_secret="` + webhookKey + `"`,
		want: []veles.Secret{
			stripeapikey.StripeWebhookSecret{Key: webhookKey},
		},
	}, {
		name:  "multiple matches",
		input: webhookKey + "\n" + webhookKey,
		want: []veles.Secret{
			stripeapikey.StripeWebhookSecret{Key: webhookKey},
			stripeapikey.StripeWebhookSecret{Key: webhookKey},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
config:
  stripe_webhook_secret: %s
end
		`, webhookKey),
		want: []veles.Secret{
			stripeapikey.StripeWebhookSecret{Key: webhookKey},
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

// TestWebhookDetector_trueNegatives tests for cases where we know the Detector
// will not find a Stripe webhook secret.
func TestWebhookDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{stripeapikey.NewWebhookSecretDetector()})
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
		input: webhookKey[:len(webhookKey)-1],
	}, {
		name:  "wrong prefix should not match",
		input: `whsecx_` + webhookKey[6:],
	}, {
		name:  "invalid character in key should not match",
		input: `whsec_51PvZzSCtJyteEjSR0hs-WRONG`,
	}, {
		name:  "prefix missing underscore should not match",
		input: `whsec51PvZzSCtJyteEjSR0hs0WOyeJUMuTk`,
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
