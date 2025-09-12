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

package apprefreshtoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/github/apprefreshtoken"
)

// Note: Github tokens are encoded using `` + `` to bypass github security checks

const (
	testKey        = `gh` + `r_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`
	anotherTestKey = `gh` + `r_Exma21WpQt8vgSQNpEiZtETooAnNLM3rnXRAPnCQYKiuWdmPRnVF0I6cW0zCgA14u7HQzD1Zebn0`
)

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Github app refresh tokens.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{apprefreshtoken.NewDetector()})
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
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
		},
	}, {
		name:  "simple matching string another key",
		input: anotherTestKey,
		want: []veles.Secret{
			apprefreshtoken.GithubAppRefreshToken{Token: anotherTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `API_TOKEN=` + testKey,
		want: []veles.Secret{
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_TOKEN="` + testKey + `"`,
		want: []veles.Secret{
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
		},
	}, {
		name:  "bad checksum",
		input: testKey[:len(testKey)-1] + "a",
		want:  []veles.Secret{},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + anotherTestKey,
		want: []veles.Secret{
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
			apprefreshtoken.GithubAppRefreshToken{Token: anotherTestKey},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:API_TOKEN: %s
		`, testKey),
		want: []veles.Secret{
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `extra`,
		want: []veles.Secret{
			apprefreshtoken.GithubAppRefreshToken{Token: testKey},
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Github app refresh tokens.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{apprefreshtoken.NewDetector()})
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
		input: `gh` + `r_OWOCPzqKuy3J4w53QpkLfff+BUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "incorrect prefix should not match",
		input: `Eop_v1_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "prefix missing dash should not match",
		input: `gh` + `rOWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
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
