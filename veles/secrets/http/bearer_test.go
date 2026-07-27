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

package http_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/http"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestBearerDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		http.NewBearerDetector(),
		"Authorization: Bearer test",
		http.BearerToken{Value: "test"},
	)
}

func TestBearerDetector_truePositives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewBearerDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		file  string
		input string
		want  []veles.Secret
	}{
		// Log formats
		{
			name: "pino_log",
			file: "logs/pino/app.log",
			want: []veles.Secret{
				http.BearerToken{Value: "pino_secret_jwt_456"},
				http.BearerToken{Value: "pino_secret_jwt_456"},
			},
		},
		{
			name: "dotnet_log",
			file: "logs/dotnet/vulnerable20260424.log",
			want: []veles.Secret{
				http.BearerToken{Value: "dotnet_prod_jwt_token_777"},
				http.BearerToken{Value: "dotnet_prod_jwt_token_777"},
			},
		},
		{
			name: "nginx_log",
			file: "logs/nginx/access.log",
			want: []veles.Secret{
				http.BearerToken{Value: "nginx_prod_jwt_token_777"},
				http.BearerToken{Value: "nginx_prod_jwt_token_777"},
			},
		},
		// Client side collections
		{
			name: "bruno",
			file: "bruno/bearer/Bearer.yml",
			want: []veles.Secret{http.BearerToken{Value: "mock-bearer"}},
		},
		{
			name: "burp_bearer_project",
			file: "burp/bearer.burp",
			want: []veles.Secret{http.BearerToken{Value: "mock-bearer"}},
		},
		{
			name: "postman",
			file: "postman/http-bearer.json",
			want: []veles.Secret{http.BearerToken{Value: "mock-bearer"}},
		},
		// Synthetic examples
		{
			name: "http_request_single_header",
			input: `GET / HTTP/1.1
Host: example.com
User-Agent: test
Authorization: Bearer example-token

`,
			want: []veles.Secret{http.BearerToken{Value: "example-token"}},
		},
		{
			name: "http_with_body_after_headers",
			input: `POST /api/login HTTP/1.1
Host: internal.local
Authorization: Bearer example-token
Content-Type: application/json
Content-Length: 12

{"x":1}
`,
			want: []veles.Secret{http.BearerToken{Value: "example-token"}},
		},
		{
			name:  "json_headers_object",
			input: `{"method":"GET","headers":{"Authorization":"Bearer example-token","Accept":"*/*"}}`,
			want:  []veles.Secret{http.BearerToken{Value: "example-token"}},
		},
		{
			name:  "json_lowercase_key_nested",
			input: `{"req":{"id":1,"headers":{"host":"app","authorization":"Bearer example-token","user-agent":"curl"}}}`,
			want:  []veles.Secret{http.BearerToken{Value: "example-token"}},
		},
		{
			name: "json_pretty_embedded_raw_header",
			input: `{
  "item": 1,
  "raw": "Authorization: Bearer example-token",
  "note": "sample"
}`,
			want: []veles.Secret{http.BearerToken{Value: "example-token"}},
		},
		{
			name: "curl_with_authorization_header_flag",
			input: `#!/bin/sh
curl -sS 'https://httpbin.org/get' \
  -H "Authorization: Bearer example-token"`,
			want: []veles.Secret{http.BearerToken{Value: "example-token"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.file != "" {
				var readErr error
				data, readErr = os.ReadFile(filepath.Join("testdata", tc.file))
				if readErr != nil {
					t.Fatal(readErr)
				}
			} else {
				data = []byte(tc.input)
			}

			got, derr := e.Detect(t.Context(), bytes.NewReader(data))
			if derr != nil {
				t.Fatal(derr)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("(-want +got): %s", diff)
			}
		})
	}
}

func TestBearerDetector_trueNegatives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewBearerDetector()})
	if err != nil {
		t.Fatal(err)
	}

	negCases := []struct {
		name  string
		file  string
		input string
	}{
		// Bearer token is present but is not detected.
		{
			// The token here is stored as a separate key and has no
			// Authorization, Bearer keyword before it, so the regex detector ignores it
			// to avoid false positives. To properly cover this case, an openCollection
			// extractor is probably the best choice.
			name: "bruno_2",
			file: "bruno/bearer/BearerProperlyStored.yml",
		},
		// Synthetic examples
		{
			name:  "not_enough_context",
			input: "I hate to be the bearer of bad news, but ...",
		},
		{
			name: "Basic_in_authorization",
			input: `GET / HTTP/1.1
Host: x
Authorization: Basic abcd-ef-ghij

`,
		},
		{
			name:  "basic_in_json",
			input: `{"headers":{"Authorization":"Basic eyJ0eXAiOiJKV1QifQ="}}`,
		},
		{
			name:  "valid_base64_decodes_without_colon",
			input: `Authorization: Basic bm9uZQ==`,
		},
	}
	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.file != "" {
				var readErr error
				data, readErr = os.ReadFile(filepath.Join("testdata", tc.file))
				if readErr != nil {
					t.Fatal(readErr)
				}
			} else {
				data = []byte(tc.input)
			}

			got, derr := e.Detect(t.Context(), bytes.NewReader(data))
			if derr != nil {
				t.Fatal(derr)
			}
			if diff := cmp.Diff([]veles.Secret(nil), got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("(-want +got): %s", diff)
			}
		})
	}
}
