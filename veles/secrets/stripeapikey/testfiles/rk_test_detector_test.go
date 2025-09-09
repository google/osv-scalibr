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

const rkTestKey = `rk_test_51PvZzmnOPQrStUvWxYzABcDEFghIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopQRSTuvWXYZabcd12345678`

// TestRKTestDetector_truePositives tests for cases where we know the Detector
// will find a Stripe RK Test key.
func TestRKTestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{stripeapikey.NewRKTestDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: rkTestKey,
		want: []veles.Secret{
			stripeapikey.StripeRKTestKey{Key: rkTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `STRIPE_RK_TEST=` + rkTestKey,
		want: []veles.Secret{
			stripeapikey.StripeRKTestKey{Key: rkTestKey},
		},
	}, {
		name:  "match in middle of string",
		input: `api_key="` + rkTestKey + `"`,
		want: []veles.Secret{
			stripeapikey.StripeRKTestKey{Key: rkTestKey},
		},
	}, {
		name:  "multiple matches",
		input: rkTestKey + "\n" + rkTestKey,
		want: []veles.Secret{
			stripeapikey.StripeRKTestKey{Key: rkTestKey},
			stripeapikey.StripeRKTestKey{Key: rkTestKey},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
config:
  stripe_rk_test: %s
end
		`, rkTestKey),
		want: []veles.Secret{
			stripeapikey.StripeRKTestKey{Key: rkTestKey},
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

// TestRKTestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Stripe RK Test key.
func TestRKTestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{stripeapikey.NewRKTestDetector()})
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
		input: `rk_live_` + rkTestKey[8:],
	}, {
		name:  "invalid character in key should not match",
		input: `rk_test_51PvZzAB-INVALID`,
	}, {
		name:  "prefix missing underscore should not match",
		input: `rktest_51PvZzmnOPQrStUvWxYz`,
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
