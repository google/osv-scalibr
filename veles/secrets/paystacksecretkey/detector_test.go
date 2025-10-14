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

package paystacksecretkey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	paystacksecretkey "github.com/google/osv-scalibr/veles/secrets/paystacksecretkey"
)

var (
	// Example valid PayStack API keys.
	detectorSK = "sk_test_" + strings.Repeat("a", 40)
)

// TestSecretKeyDetector_truePositives tests SK detection.
func TestSecretKeyDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{paystacksecretkey.NewSecretKeyDetector()},
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
			paystacksecretkey.PaystackSecret{Key: detectorSK},
		},
	}, {
		name:  "match at end of string",
		input: `PAYSTACK_KEY=` + detectorSK,
		want: []veles.Secret{
			paystacksecretkey.PaystackSecret{Key: detectorSK},
		},
	}, {
		name:  "match in quotes",
		input: `key="` + detectorSK + `"`,
		want: []veles.Secret{
			paystacksecretkey.PaystackSecret{Key: detectorSK},
		},
	}, {
		name:  "multiple matches",
		input: detectorSK + "\n" + detectorSK,
		want: []veles.Secret{
			paystacksecretkey.PaystackSecret{Key: detectorSK},
			paystacksecretkey.PaystackSecret{Key: detectorSK},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf("config:\n  api_key: %s\n",
			detectorSK),
		want: []veles.Secret{
			paystacksecretkey.PaystackSecret{Key: detectorSK},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorSK + "Extra",
		want: []veles.Secret{
			paystacksecretkey.PaystackSecret{Key: detectorSK},
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
		[]veles.Detector{paystacksecretkey.NewSecretKeyDetector()},
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
		input: detectorSK[:len(detectorSK)-40],
	}, {
		name: "invalid character in key should not match",
		input: "sk_live_" + strings.ReplaceAll(
			detectorSK[8:], "a", "!",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "pk_live_" + strings.Repeat("a", 20),
	}, {
		name:  "prefix missing underscore should not match",
		input: "sk-live_" + strings.Repeat("a", 20), // removes the underscore
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
