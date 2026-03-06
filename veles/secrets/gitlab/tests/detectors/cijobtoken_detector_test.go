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

package gitlab_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
	"github.com/google/osv-scalibr/veles/velestest"
)

var (
	// Example valid GitLab CI/CD Job Token (JWT format) - dummy data for testing
	detectorToken = "glcbt-eyJraWQiOiJBYkNkRWZHaElqS2xNbk9wUXJTdFV2V3h5WjEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJ2ZXJzaW9uIjoiMS4wLjAiLCJvIjoiMTIzIiwidSI6ImFiY2RlIiwicCI6InByb2plY3QxMjMiLCJnIjoiZ3JvdXA0NTYiLCJqdGkiOiIxMjM0NTY3OC05YWJjLTEyMzQtNTY3OC05YWJjZGVmMTIzNDUiLCJhdWQiOiJnaXRsYWItYXV0aHotdG9rZW4iLCJzdWIiOiJnaWQ6Ly9naXRsYWIvQ2k6OkJ1aWxkLzEyMzQ1Njc4OTAiLCJpc3MiOiJnaXRsYWIuY29tIiwiaWF0IjoxNjAwMDAwMDAwLCJuYmYiOjE2MDAwMDAwMDAsImV4cCI6MTYwMDAwMzYwMH0.dGhpc0lzQUR1bW15U2lnbmF0dXJlRm9yVGVzdGluZ1B1cnBvc2VzT25seUFuZFNob3VsZE5vdEJlVXNlZEluUHJvZHVjdGlvbkVudmlyb25tZW50c1RoaXNJc0p1c3RBblRleGFtcGxlVG9rZW5Gb3JUZXN0aW5nVGhlRGV0ZWN0b3JGdW5jdGlvbmFsaXR5QW5kU2hvdWxkTm90QmVDb25zaWRlcmVkQVJlYWxWYWxpZFRva2Vu"
)

func TestCIJobTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		gitlab.NewCIJobTokenDetector(),
		detectorToken,
		gitlab.CIJobToken{Token: detectorToken},
		// Use space as padding instead of 'a' since 'a' is a valid base64url character
		// Note: WithBackToBack is not used because back-to-back tokens without delimiters
		// are extremely unlikely in practice and difficult to detect reliably with regex
	)
}

// TestCIJobTokenDetector_truePositives tests token detection.
func TestCIJobTokenDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{gitlab.NewCIJobTokenDetector()},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: detectorToken,
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken},
		},
	}, {
		name:  "match at end of string",
		input: `JOB-TOKEN: ` + detectorToken,
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken},
		},
	}, {
		name:  "match in quotes",
		input: `token="` + detectorToken + `"`,
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken},
		},
	}, {
		name:  "match with gitlab.com hostname",
		input: `curl --header "JOB-TOKEN: ` + detectorToken + `" https://gitlab.com/api/v4/job`,
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken, Hostname: "gitlab.com"},
		},
	}, {
		name:  "match with self-hosted hostname",
		input: `https://gitlab.example.com/api/v4/job TOKEN=` + detectorToken,
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken, Hostname: "gitlab.example.com"},
		},
	}, {
		name:  "multiple matches",
		input: detectorToken + "\n" + detectorToken,
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken},
			gitlab.CIJobToken{Token: detectorToken},
		},
	}, {
		name: "larger_input_containing_token",
		input: fmt.Sprintf("config:\n  job_token: %s\n",
			detectorToken),
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken},
		},
	}, {
		name:  "hostname before token",
		input: `https://gitlab.internal.company.com/api/v4/projects TOKEN: ` + detectorToken,
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken, Hostname: "gitlab.internal.company.com"},
		},
	}, {
		name:  "hostname after token",
		input: detectorToken + ` for https://my-gitlab.io/api/v4/job`,
		want: []veles.Secret{
			gitlab.CIJobToken{Token: detectorToken, Hostname: "my-gitlab.io"},
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}

// TestCIJobTokenDetector_trueNegatives tests false negatives.
func TestCIJobTokenDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{gitlab.NewCIJobTokenDetector()},
	)
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
		name:  "incorrect prefix should not match",
		input: "glpat-" + detectorToken[6:],
	}, {
		name:  "missing JWT structure should not match",
		input: "glcbt-invalidtoken",
	}, {
		name:  "incomplete JWT should not match",
		input: "glcbt-eyJraWQiOiIxVHRMOTJuWlJnVHNqSVVvWDJPWVZMVU9KMWJXbUdFYmwtZkFuS3NZVWhRIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXJzaW9uIjoiMC4xLjAifQ",
	}, {
		name:  "prefix only should not match",
		input: "glcbt-",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}
