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

package github_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/github"
)

const (
	oauthTestKey        = `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`
	oauthAnotherTestKey = `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`
)

// TestOAuthDetector_truePositives tests for cases where we know the Detector
// will find a Github OAuth tokens.
func TestOAuthDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewOAuthTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: oauthTestKey,
		want: []veles.Secret{
			github.OAuthToken{Token: oauthTestKey},
		},
	}, {
		name:  "simple matching string another key",
		input: oauthAnotherTestKey,
		want: []veles.Secret{
			github.OAuthToken{Token: oauthAnotherTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `API_TOKEN=` + oauthTestKey,
		want: []veles.Secret{
			github.OAuthToken{Token: oauthTestKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_TOKEN="` + oauthTestKey + `"`,
		want: []veles.Secret{
			github.OAuthToken{Token: oauthTestKey},
		},
	}, {
		name:  "multiple matches",
		input: oauthTestKey + oauthTestKey + oauthTestKey,
		want: []veles.Secret{
			github.OAuthToken{Token: oauthTestKey},
			github.OAuthToken{Token: oauthTestKey},
			github.OAuthToken{Token: oauthTestKey},
		},
	}, {
		name:  "bad checksum",
		input: oauthTestKey[:len(oauthTestKey)-1] + "a",
		want:  []veles.Secret{},
	}, {
		name:  "multiple distinct matches",
		input: oauthTestKey + "\n" + oauthAnotherTestKey,
		want: []veles.Secret{
			github.OAuthToken{Token: oauthTestKey},
			github.OAuthToken{Token: oauthAnotherTestKey},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:API_TOKEN: %s
		`, oauthTestKey),
		want: []veles.Secret{
			github.OAuthToken{Token: oauthTestKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: oauthTestKey + `extra`,
		want: []veles.Secret{
			github.OAuthToken{Token: oauthTestKey},
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

// TestOAuthDetector_trueNegatives tests for cases where we know the Detector
// will not find a Github OAuth tokens.
func TestOAuthDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewOAuthTokenDetector()})
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
		input: oauthTestKey[:len(oauthTestKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: `gho_oJrI3NxJonXeg-4cd3v1XHDjjMk3jh2ENWzb`,
	}, {
		name:  "incorrect prefix should not match",
		input: `Eop_v1_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "bad checksum should not match",
		input: `gho_oJrI3NxJonXega4cd2v1XHDjjMk3jh2ENWzb`,
	}, {
		name:  "prefix missing dash should not match",
		input: `ghooJrI3NxJonXega4cd2v1XHDjjMk3jh2ENWzb`,
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
