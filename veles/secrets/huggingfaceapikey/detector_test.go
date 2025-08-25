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

package huggingfaceapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/huggingfaceapikey"
)

const testKey = `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`

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Huggingface API key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{huggingfaceapikey.NewDetector()})
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
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
		},
	}, {
		name:  "match at end of string",
		input: `HUGGINGFACE_API_KEY=` + testKey,
		want: []veles.Secret{
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `HUGGINGFACE_API_KEY="` + testKey + `"`,
		want: []veles.Secret{
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "a",
		want: []veles.Secret{
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey[:len(testKey)-1] + "a"},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
:test_api_key: hf-test
:huggingface_api_key: %s
		`, testKey),
		want: []veles.Secret{
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `extra`,
		want: []veles.Secret{
			huggingfaceapikey.HuggingfaceAPIKey{Key: testKey},
		},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			fmt.Printf("got = %+v\n", got)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Huggingface API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{huggingfaceapikey.NewDetector()})
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
		name:  "invalid character in key should not match",
		input: `hf_@rh6GxZ4JnSMHi3YFrpVOWH2znfcmU1WCQ`,
	}, {
		name:  "incorrect prefix should not match",
		input: `hff_ArhUGxZeJnSMHixYFrpVOWHYznfcmUWWCQ`,
	}, {
		name:  "prefix missing dash should not match",
		input: `hfSvBATDnaPfgMWAtDQmmoIMAUmzdAAlexyr`,
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
