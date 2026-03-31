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

package databrickspat

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validToken        = "dapi1234567890abcdef1234567890abcdef"
	validWorkspaceAWS = "adb-1234567890123456.12.cloud.databricks.com"
	validWorkspaceGCP = "1234567890123456.gcp.databricks.com"
	validWorkspaceAzr = "adb-1234567890123456.12.azuredatabricks.net"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		validToken+"\n"+validWorkspaceAWS,
		PATCredentials{Token: validToken, URL: validWorkspaceAWS},
	)
}

func TestDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "token_with_aws_workspace",
		input: "DATABRICKS_HOST=" + validWorkspaceAWS + "\nDATABRICKS_TOKEN=" + validToken,
		want: []veles.Secret{
			PATCredentials{Token: validToken, URL: validWorkspaceAWS},
		},
	}, {
		name:  "token_with_gcp_workspace",
		input: "host: " + validWorkspaceGCP + "\ntoken: " + validToken,
		want: []veles.Secret{
			PATCredentials{Token: validToken, URL: validWorkspaceGCP},
		},
	}, {
		name:  "token_with_azure_workspace",
		input: "host = " + validWorkspaceAzr + "\ntoken = " + validToken,
		want: []veles.Secret{
			PATCredentials{Token: validToken, URL: validWorkspaceAzr},
		},
	}, {
		name: "databrickscfg_format",
		input: `[DEFAULT]
host = ` + validWorkspaceAWS + `
token = ` + validToken,
		want: []veles.Secret{
			PATCredentials{Token: validToken, URL: validWorkspaceAWS},
		},
	}, {
		name:  "json_config",
		input: `{"host":"` + validWorkspaceGCP + `","token":"` + validToken + `"}`,
		want: []veles.Secret{
			PATCredentials{Token: validToken, URL: validWorkspaceGCP},
		},
	}, {
		name:  "token_36_chars",
		input: validWorkspaceAWS + " dapi1234567890abcdef1234567890abcdef1234",
		want: []veles.Secret{
			PATCredentials{Token: "dapi1234567890abcdef1234567890abcdef1234", URL: validWorkspaceAWS},
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

func TestDetector_NoMatches(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{{
		name:  "token_without_url",
		input: validToken,
	}, {
		name:  "url_without_token",
		input: validWorkspaceAWS,
	}, {
		name:  "wrong_prefix",
		input: validWorkspaceAWS + " xapi1234567890abcdef1234567890abcdef",
	}, {
		name:  "token_too_short",
		input: validWorkspaceAWS + " dapi123456789012345678901234567",
	}, {
		name:  "token_with_special_chars",
		input: validWorkspaceAWS + " dapi1234567890abcdef!234567890abcdef",
	}, {
		name:  "no_secrets",
		input: "This is just regular text with no secrets",
	}, {
		name:  "invalid_workspace_domain",
		input: "dapi1234567890abcdef1234567890abcdef example.databricks.invalid",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() got %v secrets, want 0", len(got))
			}
		})
	}
}
