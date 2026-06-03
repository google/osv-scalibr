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
		"Set-Cookie: session_id=23rj302jr032mr03m2r03230r",
		http.Cookie{Name: "session_id", Value: "23rj302jr032mr03m2r03230r"},
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
				http.Cookie{Name: "pino_session", Value: "xyz987"},
				http.Cookie{Name: "pino_session", Value: "xyz987"},
			},
		},
		{
			name: "dotnet_log",
			file: "logs/dotnet/vulnerable20260424.log",
			want: []veles.Secret{
				http.Cookie{Name: "session_id", Value: "abc123dotnet"},
				http.Cookie{Name: "session_id", Value: "abc123dotnet"},
			},
		},
		{
			name: "nginx_log",
			file: "logs/nginx/access.log",
			want: []veles.Secret{
				http.Cookie{Name: `tracking_id`, Value: `evil_corp_999`},
				http.Cookie{Name: `tracking_id`, Value: `evil_corp_999`},
			},
		},
		// Synthetic examples
		{
			name:  "basic single cookie",
			input: "Cookie: session_id=123456",
			want: []veles.Secret{
				http.Cookie{Name: "session_id", Value: "123456"},
			},
		},
		{
			name:  "set-cookie header",
			input: "Set-Cookie: token=super_secret",
			want: []veles.Secret{
				http.Cookie{Name: "token", Value: "super_secret"},
			},
		},
		{
			name:  "case insensitive headers",
			input: "cOokiE: mixed_case=val123",
			want: []veles.Secret{
				http.Cookie{Name: "mixed_case", Value: "val123"},
			},
		},
		{
			name:  "multiple chained cookies with spacing",
			input: "Cookie: a=1;   b=2; c=3",
			want: []veles.Secret{
				http.Cookie{Name: "a", Value: "1"},
				http.Cookie{Name: "b", Value: "2"},
				http.Cookie{Name: "c", Value: "3"},
			},
		},
		{
			name:  "base64 value with padding equals signs",
			input: "Cookie: auth=ZXhhbXBsZQ==; id=99",
			want: []veles.Secret{
				http.Cookie{Name: "auth", Value: "ZXhhbXBsZQ=="},
				http.Cookie{Name: "id", Value: "99"},
			},
		},
		{
			name:  "embedded in log line with trailing garbage text",
			input: "INFO [2026-05-21] user logged in Set-Cookie: user=admin; session=xyz123 [thread-4] status=200",
			want: []veles.Secret{
				http.Cookie{Name: "user", Value: "admin"},
				http.Cookie{Name: "session", Value: "xyz123"},
			},
		},
		{
			name:  "ignores valueless flags at the end of set-cookie",
			input: "Set-Cookie: id=123; Secure; HttpOnly",
			want: []veles.Secret{
				http.Cookie{Name: "id", Value: "123"},
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
			input: "Cookie: ",
		},
		{
			name:  "just_a_semicolon",
			input: "Cookie: ;",
		},
		{
			name:  "similar_but_different_header",
			input: "X-Forwarded-Cookie: a=1",
		},
		{
			name:  "no_equals_sign",
			input: "Cookie: just_a_name;",
		},
		{
			name:  "malformed_name_with_colon",
			input: "Cookie: a:b=1",
		},
		{
			name:  "random_key_value_pair_without_cookie_prefix",
			input: "session=12345; auth=true",
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
