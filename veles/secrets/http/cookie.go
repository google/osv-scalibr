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
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

type pattern struct {
	re             *regexp.Regexp
	postProcessing func(string) string
}

var cookiePatterns = []pattern{
	{
		// Quoted key value pairs (Logs, JSON).
		re:             regexp.MustCompile(`(?i)(?:^|[^\w-])((?:Set-)?Cookie)(?:")?\s*:\s*"((?:[^"\\]|\\.)*)"`),
		postProcessing: safeUnquote,
	},
	{
		// Unquoted HTTP Headers (HTTP dumps).
		re:             regexp.MustCompile(`(?im)^(?:[^\w-])?((?:Set-)?Cookie)[ \t]*:[ \t]+([^\r\n]+)`),
		postProcessing: func(s string) string { return s },
	},
}

type cookieDetector struct{}

// NewCookieDetector returns a Cookie detector
func NewCookieDetector() veles.Detector {
	return &cookieDetector{}
}

// Detect extracts Cookie secrets in the provided input
func (c *cookieDetector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var pos []int

	for _, pattern := range cookiePatterns {
		for _, m := range pattern.re.FindAllSubmatchIndex(data, -1) {
			// Ensure we have at least 6 indices (full match, group 1, group 2)
			if len(m) < 6 {
				continue
			}

			headerPos := m[2]
			headerType := string(data[m[2]:m[3]]) // "Cookie" or "Set-Cookie"
			rawCookies := pattern.postProcessing(string(data[m[4]:m[5]]))

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

			// Map the parsed cookies into secrets
			for _, cookie := range parsedCookies {
				if cookie.Value == "" {
					continue
				}

				secrets = append(secrets, Cookie{
					Name:  cookie.Name,
					Value: cookie.Value,
				})

				// Use the exact position of "(Set-)Cookie" for all cookies found in this header
				pos = append(pos, headerPos)
			}
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

// safeUnquote tries to unquote a string and returns it as is in case strconv.Unquote fails
func safeUnquote(s string) string {
	unquoted, err := strconv.Unquote(`"` + s + `"`)
	if err != nil {
		return s
	}
	return unquoted
}
