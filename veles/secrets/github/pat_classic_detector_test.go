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
	classicPATTestKey       = `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`
	classicPATTestKeyBase64 = `Z2hwX2xiU0g0Q1dxSEtXU0pDdGY2SmRRS25Ja002SWtWMDBOelZheA==`
	anotherClassicPATKey    = `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`
)

func TestClassicPATDetectorAcceptance(t *testing.T) {
	d := github.NewClassicPATDetector()
	cases := []struct {
		name   string
		input  string
		secret veles.Secret
	}{
		{
			name:   "raw",
			input:  classicPATTestKey,
			secret: github.ClassicPersonalAccessToken{Token: classicPATTestKey},
		},
		{
			name:   "base64",
			input:  classicPATTestKeyBase64,
			secret: github.ClassicPersonalAccessToken{Token: classicPATTestKey},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			velestest.AcceptDetector(t, d, tc.input, tc.secret, velestest.WithBackToBack(), velestest.WithPad('a'))
		})
	}
}

// TestClassicPATDetector_truePositives tests for cases where we know the Detector
// will find a Github classic personal access tokens.
func TestClassicPATDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewClassicPATDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: classicPATTestKey,
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
		},
	}, {
		name:  "simple matching string another key",
		input: anotherClassicPATKey,
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: anotherClassicPATKey},
		},
	}, {
		name:  "match at end of string",
		input: `API_TOKEN=` + classicPATTestKey,
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_TOKEN="` + classicPATTestKey + `"`,
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
		},
	}, {
		name:  "multiple matches",
		input: classicPATTestKey + classicPATTestKey + classicPATTestKey,
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
		},
	}, {
		name:  "bad checksum",
		input: classicPATTestKey[:len(classicPATTestKey)-1] + "a",
		want:  []veles.Secret{},
	}, {
		name:  "multiple distinct matches",
		input: classicPATTestKey + "\n" + anotherClassicPATKey,
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
			github.ClassicPersonalAccessToken{Token: anotherClassicPATKey},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:API_TOKEN: %s
		`, classicPATTestKey),
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: classicPATTestKey + `extra`,
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
		},
	}, {
		name:  "base64 encoded key",
		input: classicPATTestKeyBase64,
		want: []veles.Secret{
			github.ClassicPersonalAccessToken{Token: classicPATTestKey},
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

// TestClassicPATDetector_trueNegatives tests for cases where we know the Detector
// will not find a Github classic personal access tokens.
func TestClassicPATDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewClassicPATDetector()})
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
		input: classicPATTestKey[:len(classicPATTestKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: `ghr_OWOCPzqKuy3J4w53QpkLfff+BUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "incorrect prefix should not match",
		input: `Eop_v1_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "bad checksum should not match",
		input: `ghr_OWOCPzqKuy3J4w53QpkLfff+BUJSh5yLnFHj7ziyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "prefix missing dash should not match",
		input: `ghrOWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
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
