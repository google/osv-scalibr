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
	fineGrainedPATTestKey        = `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`
	fineGrainedPATTestKeyBase64  = `Z2l0aHViX3BhdF8xMUFMSkZFSUkwWmlRMTlERWVCV1NlX2FwTVZsVG5waTlVZ3FESExBa01MaDdpVng2M3RpbzlEY2tWOVJqcWFzNkg0SzVXNDVPUVpLNlN1b2c1`
	anotherFinegrainedPATTestKey = `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`
)

// TestFineGrainedPATDetector_truePositives tests for cases where we know the Detector
// will find a Github fine-grained personal access tokens.
func TestFineGrainedPATDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewFineGrainedPATDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: fineGrainedPATTestKey,
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
		},
	}, {
		name:  "simple matching string another key",
		input: anotherFinegrainedPATTestKey,
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: anotherFinegrainedPATTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `API_TOKEN=` + fineGrainedPATTestKey,
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_TOKEN="` + fineGrainedPATTestKey + `"`,
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
		},
	}, {
		name:  "multiple matches",
		input: fineGrainedPATTestKey + fineGrainedPATTestKey + fineGrainedPATTestKey,
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: fineGrainedPATTestKey + "\n" + anotherFinegrainedPATTestKey,
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
			github.FineGrainedPersonalAccessToken{Token: anotherFinegrainedPATTestKey},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:API_TOKEN: %s
		`, fineGrainedPATTestKey),
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: fineGrainedPATTestKey + `extra`,
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
		},
	}, {
		name:  "base64 encoded key",
		input: fineGrainedPATTestKeyBase64,
		want: []veles.Secret{
			github.FineGrainedPersonalAccessToken{Token: fineGrainedPATTestKey},
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

// TestFineGrainedPATDetector_trueNegatives tests for cases where we know the Detector
// will not find a Github fine-grained personal access tokens.
func TestFineGrainedPATDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{github.NewFineGrainedPATDetector()})
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
		input: fineGrainedPATTestKey[:len(fineGrainedPATTestKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: `github_pat_11ALJFEII0Zi+19DEeBWSe_apMVlTnpi9UgqDHLAkMLh7iVx63tio9DckV9Rjqas6H4K5W45OQZK6Suog5`,
	}, {
		name:  "incorrect prefix should not match",
		input: `Eop_v1_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
	}, {
		name:  "prefix missing dash should not match",
		input: `githubpat11ALJFEII0ZiQ19DEeBWSe_apMVlTnpi9UgqDHLAkMLh7iVx63tio9DckV9Rjqas6H4K5W45OQZK6Suog5`,
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
