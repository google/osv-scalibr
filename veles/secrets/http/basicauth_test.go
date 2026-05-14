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

const (
	basicB64Password123  = "YWRtaW46cGFzc3dvcmQxMjM=" // admin:password123
	basicB64UserSvcToken = "c3ZjOnRva2Vu"             // svc:token
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		http.NewBasicAuthDetector(),
		"Authorization: Basic "+basicB64Password123,
		http.BasicAuthCredentials{Username: "admin", Password: "password123"},
	)
}

func TestDetector_truePositives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewBasicAuthDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cred123 := http.BasicAuthCredentials{Username: "admin", Password: "password123"}
	credMock := http.BasicAuthCredentials{Username: "admin", Password: "mock_password"}
	credSvc := http.BasicAuthCredentials{Username: "svc", Password: "token"}

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
			want: []veles.Secret{cred123, cred123},
		},
		{
			name: "dotnet_log",
			file: "logs/dotnet/vulnerable20260424.log",
			want: []veles.Secret{cred123, cred123},
		},
		{
			name: "nginx_log",
			file: "logs/nginx/access.log",
			want: []veles.Secret{cred123, cred123},
		},
		// Client side collections
		{
			name: "bruno-1",
			file: "bruno/basic/BasicAuthHeader.yml",
			want: []veles.Secret{credMock},
		},
		{
			name: "burp_basic_auth_project",
			file: "burp/basic-auth.burp",
			want: []veles.Secret{credMock},
		},
		{
			name: "postman",
			file: "postman/http-basic.json",
			want: []veles.Secret{credMock},
		},
		// Synthetic examples
		{
			name: "http_request_single_header",
			input: `GET / HTTP/1.1
Host: example.com
User-Agent: test
Authorization: Basic ` + basicB64Password123 + `

`,
			want: []veles.Secret{cred123},
		},
		{
			name: "http_with_body_after_headers",
			input: `POST /api/login HTTP/1.1
Host: internal.local
Authorization: Basic ` + basicB64UserSvcToken + `
Content-Type: application/json
Content-Length: 12

{"x":1}
`,
			want: []veles.Secret{credSvc},
		},
		{
			name: "http_401_www_bearer_plus_basic_request_header",
			input: `HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api"
Authorization: Basic ` + basicB64Password123 + `

Unauthorized
`,
			want: []veles.Secret{cred123},
		},
		{
			name:  "json_headers_object",
			input: `{"method":"GET","headers":{"Authorization":"Basic ` + basicB64Password123 + `","Accept":"*/*"}}`,
			want:  []veles.Secret{cred123},
		},
		{
			name:  "json_lowercase_key_nested",
			input: `{"req":{"id":1,"headers":{"host":"app","authorization":"Basic ` + basicB64Password123 + `","user-agent":"curl"}}}`,
			want:  []veles.Secret{cred123},
		},
		{
			name: "json_pretty_embedded_raw_header",
			input: `{
  "item": 1,
  "raw": "Authorization: Basic ` + basicB64UserSvcToken + `",
  "note": "sample"
}`,
			want: []veles.Secret{credSvc},
		},
		{
			name: "curl_with_authorization_header_flag",
			input: `#!/bin/sh
# Explicit header: detector sees Authorization + Basic in the same span.
curl -sS 'https://httpbin.org/get' \
  -H "Authorization: Basic ` + basicB64Password123,
			want: []veles.Secret{cred123},
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

func TestDetector_trueNegatives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewBasicAuthDetector()})
	if err != nil {
		t.Fatal(err)
	}

	negCases := []struct {
		name  string
		file  string
		input string
	}{
		// Credentials are present, but not in base64 format
		//
		// Note: Detecting unencoded credentials is out of scope for the current design,
		// even though these are valid basic auth credentials rather than base64.
		{
			name: "bruno-2",
			file: "bruno/basic/BasicAuthStoredProperly.yml",
		},
		{
			name:  "curl_user_short_flag",
			input: `curl -sS -u 'admin:password123' 'https://httpbin.org/basic-auth/admin/password123'`,
		},
		{
			name:  "curl_user_long_flag",
			input: `curl --user "svc:token" 'https://internal.service.example/api/v1/healthz'`,
		},
		// Synthetic examples
		{
			name: "bearer_in_authorization",
			input: `GET / HTTP/1.1
Host: x
Authorization: Bearer abcd-ef-ghij

`,
		},
		{
			name:  "bearer_in_json",
			input: `{"headers":{"Authorization":"Bearer eyJ0eXAiOiJKV1QifQ"}}`,
		},
		{
			name: "invalid_base64_payload",
			input: `GET / HTTP/1.1
Host: y
Authorization: Basic not-valid-base64!!!

`,
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
