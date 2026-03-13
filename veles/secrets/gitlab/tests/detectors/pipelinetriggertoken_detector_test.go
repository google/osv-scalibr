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

const (
	// Example valid GitLab Pipeline Trigger Token.
	detectorToken     = "glptt-zHDqagxzUPPp5PgeBUN7"
	detectorProjectID = "49254380"
	detectorHostname  = "gitlab.com"
)

func TestPipelineTriggerTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		gitlab.NewPipelineTriggerTokenDetector(),
		detectorToken,
		gitlab.PipelineTriggerToken{Token: detectorToken},
		velestest.WithPad(' '), // Use space as padding instead of 'a'
	)
}

// TestPipelineTriggerTokenDetector_truePositives tests token detection.
func TestPipelineTriggerTokenDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{gitlab.NewPipelineTriggerTokenDetector()},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string",
		input: detectorToken,
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `TRIGGER_TOKEN=` + detectorToken,
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name:  "match_in_quotes",
		input: `token="` + detectorToken + `"`,
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name:  "multiple_matches",
		input: detectorToken + "\n" + detectorToken,
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name: "larger_input_containing_token",
		input: fmt.Sprintf("config:\n  trigger_token: %s\n",
			detectorToken),
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name:  "potential_match_longer_than_max_token_length",
		input: detectorToken + " EXTRA",
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name: "token_with_project_id_in_url",
		input: fmt.Sprintf(`curl --request POST \
--form token=%s \
--form ref=main \
"https://gitlab.com/api/v4/projects/%s/trigger/pipeline"`,
			detectorToken, detectorProjectID),
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{
				Token:     detectorToken,
				Hostname:  detectorHostname,
				ProjectID: detectorProjectID,
			},
		},
	}, {
		name: "token_with_custom_gitlab_instance",
		input: fmt.Sprintf(`curl --request POST \
--form token=%s \
--form ref=main \
"https://gitlab.example.com/api/v4/projects/%s/trigger/pipeline"`,
			detectorToken, detectorProjectID),
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{
				Token:     detectorToken,
				Hostname:  "gitlab.example.com",
				ProjectID: detectorProjectID,
			},
		},
	}, {
		name: "token_with_self_hosted_gitlab_subdomain",
		input: fmt.Sprintf(`https://git.company.io/projects/%s/trigger/pipeline
token: %s`,
			detectorProjectID, detectorToken),
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{
				Token:     detectorToken,
				Hostname:  "git.company.io",
				ProjectID: detectorProjectID,
			},
		},
	}, {
		name: "token_with_gitlab_url_without_api_path",
		input: fmt.Sprintf(`https://gitlab.internal.net/projects/%s/trigger/pipeline
TRIGGER_TOKEN=%s`,
			detectorProjectID, detectorToken),
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{
				Token:     detectorToken,
				Hostname:  "gitlab.internal.net",
				ProjectID: detectorProjectID,
			},
		},
	}, {
		name:  "token_only_without_url",
		input: fmt.Sprintf(`trigger_token: %s`, detectorToken),
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name: "token_with_project_id_key_value_no_hostname",
		input: fmt.Sprintf(`trigger_token: %s
project_id: %s`,
			detectorToken, detectorProjectID),
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name: "token_with_projectId_camelCase_no_hostname",
		input: fmt.Sprintf(`{
  "triggerToken": "%s",
  "projectId": %s
}`, detectorToken, detectorProjectID),
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: detectorToken},
		},
	}, {
		name:  "token_with_underscores",
		input: "glptt-xJwYxEM6ygnH_ooTrYMe",
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: "glptt-xJwYxEM6ygnH_ooTrYMe"},
		},
	}, {
		name:  "token_with_hyphens",
		input: "glptt-c2cpyCxbRRe5FjC-RsN4",
		want: []veles.Secret{
			gitlab.PipelineTriggerToken{Token: "glptt-c2cpyCxbRRe5FjC-RsN4"},
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

// TestPipelineTriggerTokenDetector_trueNegatives tests false negatives.
func TestPipelineTriggerTokenDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{gitlab.NewPipelineTriggerTokenDetector()},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty_input",
		input: "",
	}, {
		name:  "short_token_should_not_match",
		input: "glptt-short",
	}, {
		name:  "invalid_character_in_token_should_not_match",
		input: "glptt-zHDqwggz!PPp5PgxBUN7",
	}, {
		name:  "incorrect_prefix_should_not_match",
		input: "glxtt-" + detectorToken[6:],
	}, {
		name:  "prefix_missing_dash_should_not_match",
		input: "glptt" + detectorToken[6:], // removes the dash
	}, {
		name:  "wrong_prefix_glpat",
		input: "glpat-zHDqwggzUPPp5PgxBUN7", // GitLab PAT, not trigger token
	}, {
		name:  "wrong_prefix_gldt",
		input: "gldt-zHDqwggzUPPp5PgxBUN7", // GitLab Deploy Token, not trigger token
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
