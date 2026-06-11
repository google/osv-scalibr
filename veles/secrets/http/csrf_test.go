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
		// These testcases are real pieces of code found in the wild used to improve the
		// false positive rate of the detector
		{
			name: "aspnet_example",
			input: `|| string.Equals(requestPath, "/index.html", StringComparison.OrdinalIgnoreCase))
	    {
	        var tokenSet = antiforgery.GetAndStoreTokens(context);
	        context.Response.Cookies.Append("XSRF-TOKEN", tokenSet.RequestToken!,
	            new CookieOptions { HttpOnly = false });
	    }`,
		},
		{
			name: "angular_src_code",
			input: `
   *  - If XSRF prefix is detected, strip it
   * - **"defaults.xsrfCookieName"** - {string} - Name of cookie containing the XSRF token.
   * Defaults value is "'XSRF-TOKEN'".
   * - **"defaults.xsrfHeaderName"** - {string} - Name of HTTP header to populate with the
   * XSRF token. Defaults value is "'X-XSRF-TOKEN'".
    xsrfCookieName: 'XSRF-TOKEN',
    xsrfHeaderName: 'X-XSRF-TOKEN',
   * @name $httpProvider#xsrfTrustedOrigins
   * Array containing URLs whose origins are trusted to receive the XSRF token. See the
   * XSRF.
   *   "https://foo.com/"" will include the XSRF token.
   *   module('xsrfTrustedOriginsExample', []).
   *     $httpProvider.xsrfTrustedOrigins.push('https://api.example.com');
   *     // The XSRF token will be sent.
   *     // The XSRF token will NOT be sent.
  var xsrfTrustedOrigins = this.xsrfTrustedOrigins = [];
   * @name $httpProvider#xsrfWhitelistedOrigins
   * This property is deprecated. Use {@link $httpProvider#xsrfTrustedOrigins xsrfTrustedOrigins}
  Object.defineProperty(this, 'xsrfWhitelistedOrigins', {
      return this.xsrfTrustedOrigins;
      this.xsrfTrustedOrigins = origins;
    var urlIsAllowedOrigin = urlIsAllowedOriginFactory(xsrfTrustedOrigins);
     *  - If XSRF prefix is detected, strip it (see Security Considerations section below).
     * - [XSRF](http://en.wikipedia.org/wiki/Cross-site_request_forgery)
     * ### Cross Site Request Forgery (XSRF) Protection
     * [XSRF](http://en.wikipedia.org/wiki/Cross-site_request_forgery) is an attack technique by
     * website. AngularJS provides a mechanism to counter XSRF. When performing XHR requests, the
     * $http service reads a token from a cookie (by default, "XSRF-TOKEN") and sets it as an HTTP
     * header (by default "X-XSRF-TOKEN"). Since only JavaScript that runs on your domain could read
     * cookie called "XSRF-TOKEN" on the first HTTP GET request. On subsequent XHR requests the
     * server can verify that the cookie matches the "X-XSRF-TOKEN" HTTP header, and therefore be
     * access to your users' XSRF tokens and exposing them to Cross Site Request Forgery. If you
     * want to, you can trust additional origins to also receive the XSRF token, by adding them
     * to {@link ng.$httpProvider#xsrfTrustedOrigins xsrfTrustedOrigins}. This might be
     * See {@link ng.$httpProvider#xsrfTrustedOrigins $httpProvider.xsrfTrustedOrigins} for
     * The name of the cookie and the header can be specified using the "xsrfCookieName" and
     * "xsrfHeaderName" properties of either "$httpProvider.defaults" at config-time,
     *    - **xsrfHeaderName** – "{string}"" – Name of HTTP header to populate with the XSRF token.
     *    - **xsrfCookieName** – "{string}"" – Name of cookie containing the XSRF token.
      // if we won't have the response in cache, set the xsrf headers and
        var xsrfValue = urlIsAllowedOrigin(config.url)
            ? $$cookieReader()[config.xsrfCookieName || defaults.xsrfCookieName]
        if (xsrfValue) {
          reqHeaders[(config.xsrfHeaderName || defaults.xsrfHeaderName)] = xsrfValue;

			`,
		},
		{
			name: "politeiagui_test",
			input: `
			const mockCsrfToken = "fake_csrf";
    it("should update api state and csrf token", async () => {
        csrf: mockCsrfToken,
      expect(state.csrf).toEqual(mockCsrfToken);
      expect(state.csrf).toEqual("");`,
		},
		{
			// src: https://github.com/freeCodeCamp/freeCodeCamp/blob/main/client/src/utils/ajax.ts
			name: "freeCodeCamp_utils",
			input: `async function get<T>(
  path: string,
  signal?: AbortSignal
): Promise<ResponseWithData<T>> {
  const response = await fetch(` + "`" + `${base}${path}` + "`" + `, {
    ...defaultOptions,
    headers: { 'CSRF-Token': getCSRFToken() },
    signal
  });
  return combineDataWithResponse(response);
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
