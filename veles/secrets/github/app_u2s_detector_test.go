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
	us2TestKey        = `ghu_aGgfQsQ52sImE9zwWxKcjt2nhESfYG1U2FhX`
	u2sAnotherTestKey = `ghu_QoXdtrSAaW5sNsCFtHv8cK0ImbQxn11nVkQT`
)

// TestAppU2SDetector_truePositives tests for cases where we know the Detector
// will find a Github app user to server tokens.
func TestAppU2SDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewAppU2SDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: us2TestKey,
		want: []veles.Secret{
			github.AppUserToServerToken{Token: us2TestKey},
		},
	}, {
		name:  "simple matching string another key",
		input: u2sAnotherTestKey,
		want: []veles.Secret{
			github.AppUserToServerToken{Token: u2sAnotherTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `API_TOKEN=` + us2TestKey,
		want: []veles.Secret{
			github.AppUserToServerToken{Token: us2TestKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_TOKEN="` + us2TestKey + `"`,
		want: []veles.Secret{
			github.AppUserToServerToken{Token: us2TestKey},
		},
	}, {
		name:  "multiple matches",
		input: us2TestKey + us2TestKey + us2TestKey,
		want: []veles.Secret{
			github.AppUserToServerToken{Token: us2TestKey},
			github.AppUserToServerToken{Token: us2TestKey},
			github.AppUserToServerToken{Token: us2TestKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: us2TestKey + "\n" + u2sAnotherTestKey,
		want: []veles.Secret{
			github.AppUserToServerToken{Token: us2TestKey},
			github.AppUserToServerToken{Token: u2sAnotherTestKey},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:API_TOKEN: %s
		`, us2TestKey),
		want: []veles.Secret{
			github.AppUserToServerToken{Token: us2TestKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: us2TestKey + `extra`,
		want: []veles.Secret{
			github.AppUserToServerToken{Token: us2TestKey},
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

// TestAppU2SDetector_trueNegatives tests for cases where we know the Detector
// will not find a Github app user to server tokens.
func TestAppU2SDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewAppU2SDetector()})
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
		input: us2TestKey[:len(us2TestKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: `gh` + `u_aGgfQsQ52sImE9zwWxKcjt2nhESf^G1U2FhX`,
	}, {
		name:  "incorrect prefix should not match",
		input: `Eop_v1_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "bad checksum should not match",
		input: `gh` + `u_aGgfQsQ52sImE91wWxKcjt2nhESfYG1U2FhX`,
	}, {
		name:  "prefix missing dash should not match",
		input: `gh` + `uaGgfQsQ52sImE91wWxKcjt2nhESfYG1U2FhX`,
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
