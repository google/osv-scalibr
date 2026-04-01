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

package dropboxappaccesstoken

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

// validToken is a realistic Dropbox short-lived access token (sl. prefix + 130 chars).
const validToken = "sl.AbX9y6Fe3AuH5o66-gmJpR032jwAwQPIVVzWXZNkdzcYT02akC2de219dZi6gxYPVnYPrpvISRSf9lxKWJzYLjtMPH-d9fo_0gXex7X37VIvpty4-G8f4-WX45Aexample"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		validToken,
		AccessToken{Token: validToken},
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
		name:  "valid_token",
		input: validToken,
		want: []veles.Secret{
			AccessToken{Token: validToken},
		},
	}, {
		name:  "token_in_env_var",
		input: "DROPBOX_ACCESS_TOKEN=" + validToken,
		want: []veles.Secret{
			AccessToken{Token: validToken},
		},
	}, {
		name:  "token_in_config_file",
		input: `access_token: "` + validToken + `"`,
		want: []veles.Secret{
			AccessToken{Token: validToken},
		},
	}, {
		name:  "token_in_json",
		input: `{"access_token": "` + validToken + `"}`,
		want: []veles.Secret{
			AccessToken{Token: validToken},
		},
	}, {
		name: "multiple_tokens",
		input: validToken + "\n" +
			"sl.BcY0z7Gf4BvI6p77_hnKqS143kxBxRQJWW0oYOlezodZU13blD3fg320eAj7hzQWoYQrtJTvg0myXLKzZMkuNQI_e0gp_1hYfy8w48XIwquz5_H9g5_XY56Bfxample",
		want: []veles.Secret{
			AccessToken{Token: validToken},
			AccessToken{Token: "sl.BcY0z7Gf4BvI6p77_hnKqS143kxBxRQJWW0oYOlezodZU13blD3fg320eAj7hzQWoYQrtJTvg0myXLKzZMkuNQI_e0gp_1hYfy8w48XIwquz5_H9g5_XY56Bfxample"},
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
		name:  "empty_input",
		input: "",
	}, {
		name:  "no_secrets",
		input: "This is just regular text with no secrets",
	}, {
		name:  "sl_prefix_too_short",
		input: "sl.AbX9y6Fe3AuH5o66-gmJpR032jwAwQPIVVzWXZNkdzcYT02akC",
	}, {
		name:  "wrong_prefix",
		input: "sx." + strings.Repeat("A", 130),
	}, {
		name:  "no_prefix",
		input: strings.Repeat("A", 130),
	}, {
		name:  "sl_prefix_99_chars",
		input: "sl." + strings.Repeat("A", 99),
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
