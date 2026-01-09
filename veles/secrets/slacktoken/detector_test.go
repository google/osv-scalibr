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

package slacktoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/slacktoken"
)

const testAppLevelToken = `xapp-1-A09GDGLM2BE-9538001315143-31fd9c18d0c0c3e9638a7634d01d1ab001d3453ad209e168d5d49b589f0421af`
const testAppConfigAccessToken = `xoxe.xoxp-1-Mi0yLTk1NTI2NjcxMzI3ODYtOTU1MjY2NzEzMzI1MC05NTUyODA2ODE4OTk0LTk1NTI4MDY4MzYxOTQtNWI4NzRmYjU0MTdhZGM3MjYyZmQ5MzNjNGQwMWJhZjhmY2VhMzIyMmQ4NGY4MDZlNjkyYjM5NTMwMjFiZTgwNA`
const testAppConfigRefreshToken = `xoxe-1-My0xLTk1NTI2NjcxMzI3ODYtOTU1MjgwNjgxODk5NC05NTUyODA2ODcxNTU0LTk3Y2UxYWRlYWRlZjhhOWY5ZDRlZTVlOTI4MTRjNWZmYWZlZDU4MTU2OGZhNTIyNmVlYzY5MDE1ZmZmY2FkNTY`

// TestDetector_truePositives tests for cases where we know the Detector
// will find Slack tokens (App Level Tokens, App Configuration Access Tokens,
// and App Configuration Refresh Tokens).
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		slacktoken.NewAppLevelTokenDetector(),
		slacktoken.NewAppConfigAccessTokenDetector(),
		slacktoken.NewAppConfigRefreshTokenDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string - app level token",
		input: testAppLevelToken,
		want: []veles.Secret{
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
		},
	}, {
		name:  "match at end of string - app config refresh token",
		input: `SL_TOKEN=` + testAppConfigRefreshToken,
		want: []veles.Secret{
			slacktoken.SlackAppConfigRefreshToken{
				Token: testAppConfigRefreshToken,
			},
		},
	}, {
		name:  "match with 5 numbers in second place - app level token",
		input: "xapp-12345-A09GDGLM2BE-9538001315143-31fd9c18d0c0c3e9638a7634d01d1ab001d3453ad209e168d5d49b589f0421af",
		want: []veles.Secret{
			slacktoken.SlackAppLevelToken{
				Token: "xapp-12345-A09GDGLM2BE-9538001315143-31fd9c18d0c0c3e9638a7634d01d1ab001d3453ad209e168d5d49b589f0421af",
			},
		},
	}, {
		name:  "match in middle of string - app level token",
		input: `SL_TOKEN="` + testAppLevelToken + `"`,
		want: []veles.Secret{
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
		},
	}, {
		name:  "multiple matches - app level tokens",
		input: testAppLevelToken + testAppLevelToken + testAppLevelToken,
		want: []veles.Secret{
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
		},
	}, {
		name:  "multiple distinct matches - app level tokens",
		input: testAppLevelToken + "\n" + testAppLevelToken[:len(testAppLevelToken)-1] + "a",
		want: []veles.Secret{
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken[:len(testAppLevelToken)-1] + "a",
			},
		},
	}, {
		name: "larger_input_containing_key_-_app_level_token",
		input: fmt.Sprintf(`
:test_api_key: do-test
:SL_TOKEN: %s
		`, testAppLevelToken),
		want: []veles.Secret{
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
		},
	}, {
		name:  "potential match longer than max key length - app level token",
		input: testAppLevelToken + `extra`,
		want: []veles.Secret{
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
		},
	}, {
		name:  "app config access token",
		input: testAppConfigAccessToken,
		want: []veles.Secret{
			slacktoken.SlackAppConfigAccessToken{
				Token: testAppConfigAccessToken,
			},
		},
	}, {
		name:  "app config refresh token",
		input: testAppConfigRefreshToken,
		want: []veles.Secret{
			slacktoken.SlackAppConfigRefreshToken{
				Token: testAppConfigRefreshToken,
			},
		},
	}, {
		name:  "multiple token types",
		input: testAppLevelToken + "\n" + testAppConfigAccessToken + "\n" + testAppConfigRefreshToken,
		want: []veles.Secret{
			slacktoken.SlackAppLevelToken{
				Token: testAppLevelToken,
			},
			slacktoken.SlackAppConfigAccessToken{
				Token: testAppConfigAccessToken,
			},
			slacktoken.SlackAppConfigRefreshToken{
				Token: testAppConfigRefreshToken,
			},
		},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			fmt.Printf("got = %+v\n", got)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find Slack tokens (App Level Tokens, App Configuration Access Tokens,
// and App Configuration Refresh Tokens).
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		slacktoken.NewAppLevelTokenDetector(),
		slacktoken.NewAppConfigAccessTokenDetector(),
		slacktoken.NewAppConfigRefreshTokenDetector(),
	})
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
		name:  "short app level token should not match",
		input: testAppLevelToken[:len(testAppLevelToken)-1],
	}, {
		name:  "more than 10 numbers in second place should not match - app level token",
		input: "xapp-12345678910-A09GDGLM2BE-9538001315143-31fd9c18d0c0c3e9638a7634d01d1ab001d3453ad209e168d5d49b589f0421af",
	}, {
		name:  "invalid character in app level token should not match",
		input: `xapp-1-A09GDGLM2BE-9538001315143-31fd9c18d0c0c3e9638a7634d01d1ab001d3453ad209e168d5d49b589f0421ag`, // 'g' instead of 'f'
	}, {
		name:  "incorrect prefix for app level token should not match",
		input: `zapp-2-B09GDGLM2BE-9538001315143-31fd9c18d0c0c3e9638a7634d01d1ab001d3453ad209e168d5d49b589f0421af`,
	}, {
		name:  "app level token prefix missing dash should not match",
		input: `xapp1-A09GDGLM2BE-9538001315143-31fd9c18d0c0c3e9638a7634d01d1ab001d3453ad209e168d5d49b589f0421af`,
	}, {
		name:  "short app config access token should not match",
		input: testAppConfigAccessToken[:len(testAppConfigAccessToken)-1],
	}, {
		name: "invalid_character_in_app_config_access_token_should_not_match",
		input: testAppConfigAccessToken[:len(testAppConfigAccessToken)-2] +
			"@" +
			testAppConfigAccessToken[len(testAppConfigAccessToken)-1:],
	}, {
		name:  "short app config refresh token should not match",
		input: testAppConfigRefreshToken[:len(testAppConfigRefreshToken)-1],
	}, {
		name: "invalid_character_in_app_config_refresh_token_should_not_match",
		input: testAppConfigRefreshToken[:len(testAppConfigRefreshToken)-2] +
			"!" +
			testAppConfigRefreshToken[len(testAppConfigRefreshToken)-1:],
	}, {
		name:  "invalid app config access token prefix should not match",
		input: `xoxe.xoxq-1-Mi0yLTk1NTI2NjcxMzI3ODYtOTU1MjY2NzEzMzI1MC05NTUyODA2ODE4OTk0LTk1NTI4MDY4MzYxOTQtNWI4NzRmYjU0MTdhZGM3MjYyZmQ5MzNjNGQwMWJhZjhmY2VhMzIyMmQ4NGY4MDZlNjkyYjM5NTMwMjFiZTgwNA`, // 'xoxq' instead of 'xoxp'
	}, {
		name:  "invalid app config refresh token prefix should not match",
		input: `xoxf-1-My0xLTk1NTI2NjcxMzI3ODYtOTU1MjgwNjgxODk5NC05NTUyODA2ODcxNTU0LTk3Y2UxYWRlYWRlZjhhOWY5ZDRlZTVlOTI4MTRjNWZmYWZlZDU4MTU2OGZhNTIyNmVlYzY5MDE1ZmZmY2FkNTY`, // 'xoxf' instead of 'xoxe'
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
