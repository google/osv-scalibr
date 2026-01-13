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
	s2sTestKey        = `ghs_oJrI3NxJonXega4cd3v1XHDjjMk3jh2ENWzb`
	s2sTestKeyBase64  = `Z2hzX29KckkzTnhKb25YZWdhNGNkM3YxWEhEampNazNqaDJFTld6Yg==`
	s2sAnotherTestKey = `ghs_DCASJRv332FYglZzXPw7n0onKEqqt50ugSfn`
)

// TestAppS2SDetector_truePositives tests for cases where we know the Detector
// will find a Github app server to server tokens.
func TestAppS2SDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewAppS2STokenDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: s2sTestKey,
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sTestKey},
		},
	}, {
		name:  "simple matching string another key",
		input: s2sAnotherTestKey,
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sAnotherTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `API_TOKEN=` + s2sTestKey,
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sTestKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_TOKEN="` + s2sTestKey + `"`,
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sTestKey},
		},
	}, {
		name:  "multiple matches",
		input: s2sTestKey + s2sTestKey + s2sTestKey,
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sTestKey},
			github.AppServerToServerToken{Token: s2sTestKey},
			github.AppServerToServerToken{Token: s2sTestKey},
		},
	}, {
		name:  "bad checksum",
		input: s2sTestKey[:len(s2sTestKey)-1] + "a",
		want:  []veles.Secret{},
	}, {
		name:  "multiple distinct matches",
		input: s2sTestKey + "\n" + s2sAnotherTestKey,
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sTestKey},
			github.AppServerToServerToken{Token: s2sAnotherTestKey},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:API_TOKEN: %s
		`, s2sTestKey),
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sTestKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: s2sTestKey + `extra`,
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sTestKey},
		},
	}, {
		name:  "base64 encoded key",
		input: s2sTestKeyBase64,
		want: []veles.Secret{
			github.AppServerToServerToken{Token: s2sTestKey},
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

// TestAppS2SDetector_trueNegatives tests for cases where we know the Detector
// will not find a Github app server to server tokens.
func TestAppS2SDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewAppS2STokenDetector()})
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
		input: s2sTestKey[:len(s2sTestKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: `ghs_oJrI3NxJonXeg-4cd3v1XHDjjMk3jh2ENWzb`,
	}, {
		name:  "incorrect prefix should not match",
		input: `Eop_v1_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "bad checksum should not match",
		input: `ghs_oJrI3NxJonXega4cd2v1XHDjjMk3jh2ENWzb`,
	}, {
		name:  "prefix missing dash should not match",
		input: `ghsoJrI3NxJonXega4cd2v1XHDjjMk3jh2ENWzb`,
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
