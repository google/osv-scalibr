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

const skTestKey = `sk_test_51PvZzmSCtJyteEjSR0hs0WOyeJUMuTkTxwmrkJiFggLswv1CHxsJiwgFBT1JF9MdwNw4PJgzYncXs1yPWPQMq372006sC0Cder`

// TestSKTestDetector_truePositives tests for cases where we know the Detector
// will find a Stripe SK Test key.
func TestSKTestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{stripeapikey.NewSKTestDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: skTestKey,
		want: []veles.Secret{
			stripeapikey.StripeSKTestKey{Key: skTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `STRIPE_SK_TEST=` + skTestKey,
		want: []veles.Secret{
			stripeapikey.StripeSKTestKey{Key: skTestKey},
		},
	}, {
		name:  "match in middle of string",
		input: `api_key="` + skTestKey + `"`,
		want: []veles.Secret{
			stripeapikey.StripeSKTestKey{Key: skTestKey},
		},
	}, {
		name:  "multiple matches",
		input: skTestKey + "\n" + skTestKey,
		want: []veles.Secret{
			stripeapikey.StripeSKTestKey{Key: skTestKey},
			stripeapikey.StripeSKTestKey{Key: skTestKey},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
config:
  stripe: %s
end
		`, skTestKey),
		want: []veles.Secret{
			stripeapikey.StripeSKTestKey{Key: skTestKey},
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

// TestSKTestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Stripe SK Test key.
func TestSKTestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{stripeapikey.NewSKTestDetector()})
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
		name:  "wrong prefix should not match",
		input: `sk_live_` + skTestKey[8:],
	}, {
		name:  "invalid character in key should not match",
		input: `sk_test_51PvZzAB-INVALID`,
	}, {
		name:  "prefix missing underscore should not match",
		input: `sktest_51PvZzmSCtJyteEjSR0hs0WOyeJUMuTkTxwmrkJiFgg`,
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
