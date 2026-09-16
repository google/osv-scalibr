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

func TestCookieDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		http.NewCookieDetector(),
		`HTTP/1.1 200 896 Cookie: "session_id=23rj302jr032mr03m2r03230r"`,
		http.Cookie{Values: map[string]string{"session_id": "23rj302jr032mr03m2r03230r"}},
	)
}

func TestCookieDetector_truePositives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewCookieDetector()})
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
				http.Cookie{Values: map[string]string{"pino_session": "xyz987"}},
				http.Cookie{Values: map[string]string{"pino_session": "xyz987"}},
			},
		},
		{
			name: "dotnet_log",
			file: "logs/dotnet/vulnerable20260424.log",
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"session_id": "abc123dotnet"}},
				http.Cookie{Values: map[string]string{"session_id": "abc123dotnet"}},
			},
		},
		{
			name: "nginx_log",
			file: "logs/nginx/access.log",
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"tracking_id": "evil_corp_999"}},
				http.Cookie{Values: map[string]string{"tracking_id": "evil_corp_999"}},
			},
		},
		// Synthetic examples
		{
			name:  "basic_single_cookie",
			input: "Content-Type: text/html\nCookie: session_id=123456",
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"session_id": "123456"}},
			},
		},
		{
			name:  "quoted and encoded",
			input: "Content-Type: text/html\n" + `Cookie: "session_id=\"123456\""`,
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"session_id": "123456"}},
			},
		},
		{
			name:  "set-cookie_header",
			input: "Content-Type: application/json\nSet-Cookie: token=super_secret",
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"token": "super_secret"}},
			},
		},
		{
			name:  "case_insensitive_headers",
			input: "content-type: application/json\ncOokiE: mixed_case=val123",
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"mixed_case": "val123"}},
			},
		},
		{
			name:  "multiple_chained_cookies_with_spacing",
			input: "Content-Type: text/html\nCookie: a=1;   b=2; c=3",
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"a": "1", "b": "2", "c": "3"}},
			},
		},
		{
			name:  "base64_value_with_padding_equals_signs",
			input: "Content-Type: text/html\nCookie: auth=ZXhhbXBsZQ==; id=99",
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"auth": "ZXhhbXBsZQ==", "id": "99"}},
			},
		},
		{
			name:  "embedded_in_log_line_with_trailing_garbage_text",
			input: `INFO [2026-05-21] content-type: application/json user logged in Cookie: "user=admin; session=xyz123" [thread-4] status=200`,
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"user": "admin", "session": "xyz123"}},
			},
		},
		{
			name:  "ignores_valueless_flags_at_the_end_of_set-cookie",
			input: "Content-Type: application/json\nSet-Cookie: id=123; Secure; HttpOnly",
			want: []veles.Secret{
				http.Cookie{Values: map[string]string{"id": "123"}},
			},
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

func TestCookieDetector_trueNegatives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewCookieDetector()})
	if err != nil {
		t.Fatal(err)
	}

	negCases := []struct {
		name  string
		file  string
		input string
	}{
		// Cookie is present but is not detected.
		{
			// There is not enough context to properly detect the cookie, this case will probably never be covered
			name: "postman",
			file: "postman/cookie.json",
		},
		{
			// It would be nice to cover this case but at the current stage of the detector it would lead over-complication and
			// potential false positives
			name: "cookie_in_open_collection",
			file: "bruno/cookie/Auth.yml",
		},
		// Cookie not present
		{
			name: "missing_cookie_in_open_collection",
			file: "bruno/cookie/UnAuth.yml",
		},
		// Synthetic examples
		{
			name:  "empty_cookie_header",
			input: "Content-Type: text/html\nCookie: ",
		},
		{
			name:  "just_a_semicolon",
			input: "Content-Type: text/html\nCookie: ;",
		},
		{
			name:  "similar_but_different_header",
			input: "Content-Type: text/html\nX-Forwarded-Cookie: a=1",
		},
		{
			name:  "no_equals_sign",
			input: "Content-Type: text/html\nCookie: just_a_name;",
		},
		{
			name:  "malformed_name_with_colon",
			input: "Content-Type: text/html\nCookie: a:b=1",
		},
		{
			name:  "random_key_value_pair_without_cookie_prefix",
			input: "Content-Type: text/html\nsession=12345; auth=true",
		},
		{
			name:  "missing_context_keyword",
			input: "Cookie: session_id=123456",
		},
		// Potential false positives from source code syntax
		{
			name: "js_object_destructuring",
			input: `
			// Fake js comment to test the main regex functionality: Content-Type: "application/json"
			const { cookie: session_token=null } = req.headers;`,
		},
		{
			name:  "js_assignment_operator",
			input: `const metrics = { Content-Type: "application/json", cookie: index+=1, other_header: 0 };`,
		},
		{
			name: "python_equality_check",
			input: `
			# Fake python comment to test the main regex functionality: Content-Type: "application/json"
			rules = { "cookie": incoming_type=="admin" }`,
		},
		{
			name:  "env_var_interpolation",
			input: `curl -H "User-Agent: curl/8.4.0" -H "Cookie: session_id=${LATEST_SESSION}" https://api.example.com`,
		},
		// Real-world inspired examples
		{
			// Quoted list literal, no key=value pair, header not at line start
			name: "quoted_list_literal_without_value_assignment",
			input: `
			fingerprints = [
				'Content-Type: application/json'
				'Set-Cookie: PHPSESSID:-php',
				'Set-Cookie: laravel_session:-laravel',
				'Set-Cookie: wp-settings-:-wordpress',
			]
			`,
		},
		{
			// Header embedded inside a function-call argument, not at line start
			name: "header_embedded_in_function_call_argument",
			input: `
			User-Agent: Mozilla/5.0
			test("set-cookie: CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT");
			test("Set-Cookie2:Customer=\"WILE_E_COYOTE\"; Version=\"1\"; Path=\"/acme\"");
			`,
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
