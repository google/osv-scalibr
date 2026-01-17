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
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	refreshTestKey        = `ghr_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`
	refreshTestKeyBase64  = `Z2hyX09XT0NQenFLdXkzSjR3NTNRcGtMZmZmakJVSlNoNXlMbkZIajd3aXlSME5EYWRWT2N5a05rb3Fob1lZWE0xeXkyc09wQXUwbEc4Znc=`
	refreshAnotherTestKey = `ghr_Exma21WpQt8vgSQNpEiZtETooAnNLM3rnXRAPnCQYKiuWdmPRnVF0I6cW0zCgA14u7HQzD1Zebn0`
)

func TestAppRefreshTokenDetectorAcceptance(t *testing.T) {
	d := github.NewAppRefreshTokenDetector()
	cases := []struct {
		name   string
		input  string
		secret veles.Secret
		opts   []velestest.AcceptDetectorOption
	}{
		{
			name:   "raw",
			input:  refreshTestKey,
			secret: github.AppRefreshToken{Token: refreshTestKey},
			opts: []velestest.AcceptDetectorOption{
				velestest.WithBackToBack(),
				velestest.WithPad('a'),
			},
		},
		{
			name:   "base64",
			input:  refreshTestKeyBase64,
			secret: github.AppRefreshToken{Token: refreshTestKey},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			velestest.AcceptDetector(t, d, tc.input, tc.secret, tc.opts...)
		})
	}
}

// TestAppRefreshTokenDetector_truePositives tests for cases where we know the Detector
// will find a Github app refresh tokens.
func TestAppRefreshTokenDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewAppRefreshTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: refreshTestKey,
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshTestKey},
		},
	}, {
		name:  "simple matching string another key",
		input: refreshAnotherTestKey,
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshAnotherTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `API_TOKEN=` + refreshTestKey,
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshTestKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_TOKEN="` + refreshTestKey + `"`,
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshTestKey},
		},
	}, {
		name:  "multiple matches",
		input: refreshTestKey + refreshTestKey + refreshTestKey,
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshTestKey},
			github.AppRefreshToken{Token: refreshTestKey},
			github.AppRefreshToken{Token: refreshTestKey},
		},
	}, {
		name:  "bad checksum",
		input: refreshTestKey[:len(refreshTestKey)-1] + "a",
		want:  []veles.Secret{},
	}, {
		name:  "multiple distinct matches",
		input: refreshTestKey + "\n" + refreshAnotherTestKey,
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshTestKey},
			github.AppRefreshToken{Token: refreshAnotherTestKey},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:API_TOKEN: %s
		`, refreshTestKey),
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshTestKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: refreshTestKey + `extra`,
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshTestKey},
		},
	}, {
		name:  "base64 encoded key",
		input: refreshTestKeyBase64,
		want: []veles.Secret{
			github.AppRefreshToken{Token: refreshTestKey},
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

// TestAppRefreshTokenDetector_trueNegatives tests for cases where we know the Detector
// will not find a Github app refresh tokens.
func TestAppRefreshTokenDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewAppRefreshTokenDetector()})
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
		input: refreshTestKey[:len(refreshTestKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: `gh` + `r_OWOCPzqKuy3J4w53QpkLfff+BUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "incorrect prefix should not match",
		input: `Eop_v1_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "bad checksum should not match",
		input: `gh` + `r_OWOCPzqKuy3J4w53QpkLfff+BUJSh5yLnFHj7ziyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
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
