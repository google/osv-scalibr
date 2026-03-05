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

package rubygemsapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/rubygemsapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testKey = `rubygems_cec9db9373ea171daaaa0bf2337edce187f09558cb19c1b2`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		rubygemsapikey.NewDetector(),
		testKey,
		rubygemsapikey.RubyGemsAPIKey{Key: testKey},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a RubyGems API key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{rubygemsapikey.NewDetector()})
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
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
		},
	}, {
		name:  "match at end of string",
		input: `RUBYGEMS_API_KEY=` + testKey,
		want: []veles.Secret{
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `RUBYGEMS_API_KEY="` + testKey + `"`,
		want: []veles.Secret{
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "1\n",
		want: []veles.Secret{
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
			rubygemsapikey.RubyGemsAPIKey{Key: testKey[:len(testKey)-1] + "1"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: rubygems_abc
:rubygems_api_key: %s 
		`, testKey),
		want: []veles.Secret{
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `test`,
		want: []veles.Secret{
			rubygemsapikey.RubyGemsAPIKey{Key: testKey},
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
// will not find a RubyGems API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{rubygemsapikey.NewDetector()})
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
		name:  "special character in key should not match",
		input: `rubygems_cec9db9373ea171daaaa0bf2337edce187f09558cb19c1b.`,
	}, {
		name:  "special character in prefix should not match",
		input: `ruby.gems_cec9db9373ea171daaaa0bf2337edce187f09558cb19c1b2`,
	}, {
		name:  "special character after prefix should not match",
		input: `rubygems_.cec9db9373ea171daaaa0bf2337edce187f09558cb19c1b2`,
	}, {
		name:  "incorrect casing of prefix should not match",
		input: `rubyGEMS_cec9db9373ea171daaaa0bf2337edce187f09558cb19c1b2`,
	}, {
		name:  "invalid casing in key should not match",
		input: `rubygems_cec9db9373ea171daaaa0bf2337EDCE187f09558cb19c1b2`,
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
