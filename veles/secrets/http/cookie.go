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

package http

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

var (
	// cookiePattern captures the entire Cookie or Set-Cookie header value.
	// Supports strict RFC 6265 AND legacy RFC 2109/2965 escaped quoted strings.
	cookiePattern = regexp.MustCompile(
		// Header key
		`(?i)(?:^|[^\w-])((?:Set-)?Cookie)(?:")?\s*:\s*(?:")?` +
			`(` +
			// Cookie name (Strict RFC token, see: https://www.rfc-editor.org/info/rfc2616/#section-2.2)
			`[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+` +
			// Equal sign
			`=` +
			// Cookie value (Supports Legacy Escaping)
			// Matches:
			//   - A quoted string that allows escaped characters like \" or \\
			//   - A strict unquoted string
			`(?:"(?:[^"\\]|\\.)*"|[^\s;",\\]*)` +
			// Same pattern but preceded by a `; `
			`(?:\s*;\s*[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+(?:=(?:"(?:[^"\\]|\\.)*"|[^\s;",\\]*))?)*` +
			`)`,
	)
)

type cookieDetector struct{}

// NewCookieDetector returns a Cookie detector
func NewCookieDetector() veles.Detector {
	return &cookieDetector{}
}

// Detect extracts Cookie secrets in the provided input
func (c *cookieDetector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var pos []int

	for _, m := range cookiePattern.FindAllSubmatchIndex(data, -1) {
		// Ensure we have at least 6 indices:
		if len(m) < 6 {
			continue
		}

		headerPos := m[2]
		headerType := string(data[m[2]:m[3]]) // "Cookie" or "Set-Cookie"
		rawCookies := string(data[m[4]:m[5]])

		header := http.Header{}
		header.Add(headerType, rawCookies)

		// use golang std lib to parse the cookie
		var parsedCookies []*http.Cookie
		if strings.EqualFold(headerType, "Cookie") {
			var err error
			parsedCookies, err = http.ParseCookie(rawCookies)
			if err != nil {
				continue
			}
		} else {
			parsedCookie, err := http.ParseSetCookie(rawCookies)
			if err != nil {
				continue
			}
			parsedCookies = append(parsedCookies, parsedCookie)
		}

		// Map the cookies into secrets
		for _, cookie := range parsedCookies {
			if cookie.Value == "" {
				continue
			}

			// TODO: filter out using white/black-list

			secrets = append(secrets, Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			})

			// Use the exact position of "(Set-)Cookie" for all cookies found in this header
			pos = append(pos, headerPos)
		}
	}

	return secrets, pos
}

// MaxSecretLen returns the maximum length that a Cookie secret is expected to be
func (c *cookieDetector) MaxSecretLen() uint32 {
	// MaxLen is set based on practical limits in common HTTP infrastructure:
	// - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html#http-headers-quotas
	// - https://nodejs.org/api/cli.html#max-http-header-sizesize
	// - https://httpd.apache.org/docs/current/mod/core.html#limitrequestfieldsize
	return 16 * veles.KiB
}
