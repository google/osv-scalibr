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

package cloudflareapitoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/cloudflareapitoken"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testKey = `7awgM4jG5SQvxcvmNzhKj8PQjxo7awgM4jG5SQvx`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		cloudflareapitoken.NewDetector(),
		"CLOUDFLARE_API_TOKEN="+testKey,
		cloudflareapitoken.CloudflareAPIToken{Token: testKey},
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Cloudflare API Token/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{cloudflareapitoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "CLOUDFLARE_API_TOKEN environment variable",
			input: `CLOUDFLARE_API_TOKEN="` + testKey + `"`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "CLOUDFLARE_API_KEY environment variable",
			input: `CLOUDFLARE_API_KEY=` + testKey,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "CF_API_TOKEN environment variable",
			input: `CF_API_TOKEN='` + testKey + `'`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "CF_API_KEY environment variable",
			input: `CF_API_KEY=` + testKey,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "CLOUDFLARE_TOKEN environment variable",
			input: `CLOUDFLARE_TOKEN="` + testKey + `"`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "CF_TOKEN environment variable",
			input: `CF_TOKEN=` + testKey,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "CLOUDFLARE_AUTH_KEY environment variable",
			input: `CLOUDFLARE_AUTH_KEY="` + testKey + `"`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "CF_ACCOUNT_ID environment variable",
			input: `CF_ACCOUNT_ID=` + testKey,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "lowercase cloudflare_api_token environment variable",
			input: `cloudflare_api_token=` + testKey,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "lowercase cf_api_key environment variable",
			input: `cf_api_key="` + testKey + `"`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "JSON format with CLOUDFLARE_API_TOKEN",
			input: `{"CLOUDFLARE_API_TOKEN": "` + testKey + `"}`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "JSON format with CLOUDFLARE_API_TOKEN with whitespaces",
			input: `{"CLOUDFLARE_API_TOKEN" : " ` + testKey + ` " }`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "YAML format with cloudflare_api_token",
			input: `cloudflare_api_token: "` + testKey + `"`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "YAML format with cloudflare_api_token with whitespaces",
			input: `cloudflare_api_token: " ` + testKey + ` "`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name: "YAML format with nested cloudflare config",
			input: `cloudflare:
  CLOUDFLARE_API_TOKEN: "` + testKey + `"`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "YAML without quotes",
			input: `cf_api_key: ` + testKey,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "case insensitive matching",
			input: `Cloudflare_Api_Token="` + testKey + `"`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name: "multiple matches with different keywords",
			input: `CLOUDFLARE_API_TOKEN="` + testKey + `"
CF_API_KEY=` + testKey[:len(testKey)-1] + `a`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey[:len(testKey)-1] + "a"},
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name: "larger config file with cloudflare token",
			input: fmt.Sprintf(`
server:
  port: 8080
cloudflare:
  CLOUDFLARE_API_TOKEN: %s
  zone_id: abcd1234
database:
  host: localhost
				`, testKey),
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
		{
			name:  "token with extra whitespace around assignment",
			input: `CLOUDFLARE_API_TOKEN  =  "` + testKey + `"`,
			want: []veles.Secret{
				cloudflareapitoken.CloudflareAPIToken{Token: testKey},
			},
		},
	}
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Cloudflare API Token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{cloudflareapitoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "token without context keyword",
			input: testKey,
		},
		{
			name:  "short key should not match",
			input: `CLOUDFLARE_API_TOKEN="` + testKey[:len(testKey)-1] + `"`,
		},
		{
			name:  "invalid character in key should not match",
			input: `CLOUDFLARE_API_TOKEN="7a@wgM4jG5SQvxcvmNzhKj8PQjxo7awgM4jG5SQ"`,
		},
		{
			name:  "token too long should not match",
			input: `CLOUDFLARE_API_TOKEN="` + testKey + `a"`,
		},
		{
			name:  "malformed assignment",
			input: `CLOUDFLARE_API_TOKEN` + testKey,
		},
	}
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
