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

func TestCSRFTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		http.NewCSRFTokenDetector(),
		`csrf_token":"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"`,
		http.CSRFToken{Value: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"},
	)
}

func TestCSRFTokenDetector_truePositives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewCSRFTokenDetector()})
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
				http.CSRFToken{Value: "pino_csrf_token_98765"},
				http.CSRFToken{Value: "pino_csrf_token_98765"},
			},
		},
		{
			name: "dotnet_log",
			file: "logs/dotnet/vulnerable20260424.log",
			want: []veles.Secret{
				http.CSRFToken{Value: "dotnet_csrf_token_98765"},
			},
		},
		{
			name: "nginx_log",
			file: "logs/nginx/access.log",
			want: []veles.Secret{
				http.CSRFToken{Value: "nginx_csrf_token_98765"},
			},
		},
		// Synthetic examples
		{
			name:  "json_payload",
			input: `{"csrfToken": "abc123def456ghi789jkl012mno345pq"}`,
			want: []veles.Secret{
				http.CSRFToken{Value: "abc123def456ghi789jkl012mno345pq"},
			},
		},
		{
			name:  "xsrf_variant",
			input: `XSRF-TOKEN: 9876543210fedcba9876543210fedcba`,
			want: []veles.Secret{
				http.CSRFToken{Value: "9876543210fedcba9876543210fedcba"},
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

func TestCSRFTokenDetector_trueNegatives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewCSRFTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}

	negCases := []struct {
		name  string
		file  string
		input string
	}{
		{
			// CSRF token present but not detected, this will be detected by the cookie detector
			name:  "synthetic_csrf_cookie",
			input: `Set-Cookie: csrf_cookie=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6; Path=/`,
		},
		{
			// CSRF token present but not detected to reduce false positives
			name:  "html_hidden_input",
			input: `<input type="hidden" name="csrfmiddlewaretoken" value="django1234567890abcdefghijklmnop">`,
		},
		{
			// CSRF token present but not detected to reduce false positives
			name:  "csrf_token_assignment",
			input: `csrf_token = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'`,
		},
		{
			name:  "empty_input",
			input: ``,
		},
		{
			name:  "random_text",
			input: `Just some random text without any tokens.`,
		},
		{
			name:  "short_token_value",
			input: `csrf_token = "abc"`,
		},
		{
			name:  "unrelated_variable_assignment",
			input: `session_id = "1234567890abcdef1234567890abcdef"`,
		},

		{
			name:  "bearer_token",
			input: `Authorization: Bearer abcdef1234567890abcdef1234567890`,
		},
		{
			name:  "csrf_token_named_in_paragraph",
			input: " * This CSRF token manager uses a combination of cookie and headers to validate non-persistent tokens.",
		},
		{
			name:  "variable_assignment",
			input: `csrf_header_name = "Custom-XSRF-Header-a1b2c3d4"`,
		},
		// These testcases are inspired by real-world code patterns
		{
			// Token name passed as a positional argument to a cookie-setter call; the actual
			// value is a variable reference, not a quoted literal
			name: "token_name_as_positional_argument",
			input: `public IActionResult IssueToken()
{
    var tokenSet = _antiforgery.GetAndStoreTokens(HttpContext);
    Response.Cookies.Append("XSRF-TOKEN", tokenSet.RequestToken, new CookieOptions { HttpOnly = false });
    return Ok();
}`,
		},
		{
			// Property names like xsrfCookieName/xsrfHeaderName carry a suffix the keyword
			// regex doesn't allow directly after xsrf/csrf
			name: "xsrf_config_property_name_suffix",
			input: `const httpDefaults = {
  xsrfHeaderName: 'X-XSRF-TOKEN',
  xsrfCookieName: 'XSRF-TOKEN',
};`,
		},
		{
			// Value is a variable reference on an indented line, not a quoted literal at line start
			name: "token_value_is_variable_reference",
			input: `function buildAuthState(mockCsrfToken) {
  return {
    csrf: mockCsrfToken,
    isAuthenticated: true,
  };
}`,
		},
		{
			// Header value comes from a function call, not a quoted literal
			name: "token_value_from_function_call",
			input: `async function fetchWithCsrf<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: { 'CSRF-Token': getCsrfToken() },
  });
  return response.json();
}`,
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
