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

package cratesioapitoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/cratesioapitoken"
)

const testKey = `cioAbCdEfGhIjKlMnOpQrStUvWxYz123456`

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Crates.io API key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{cratesioapitoken.NewDetector()})
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
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
		},
	}, {
		name:  "match at end of string",
		input: `CIO_API_TOKEN=` + testKey,
		want: []veles.Secret{
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `CIO_API_TOKEN="` + testKey + `"`,
		want: []veles.Secret{
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "a",
		want: []veles.Secret{
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
			cratesioapitoken.CratesIOAPItoken{Token: testKey[:len(testKey)-1] + "a"},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
	:test_api_key: cio-test
	:CIO_API_TOKEN: %s
			`, testKey),
		want: []veles.Secret{
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `extra`,
		want: []veles.Secret{
			cratesioapitoken.CratesIOAPItoken{Token: testKey},
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
// will not find a Crates.io API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{cratesioapitoken.NewDetector()})
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
		input: `cioAbCdEfGhIjKl@nOpQrStUvWxYz123456`,
	}, {
		name:  "incorrect prefix should not match",
		input: `EioAbCdEfGhIjKlMnOpQrStUvWxYz123456`,
	}, {
		name:  "prefix missing dash should not match",
		input: `AbCdEfGhIjKlMnOpQrStUvWxYz123456`,
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
