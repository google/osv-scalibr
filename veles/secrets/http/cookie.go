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
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

var (
	// cookiePattern captures the entire cookie header value
	cookiePattern = regexp.MustCompile(
		// Cookie header key
		`(?i)(?:^|[^\w-])((?:Set-)?Cookie)(?:")?\s*:\s*(?:")?` +
			`(` +
			// Cookie name
			`[^=\s;:]+` +
			// Equal sign
			`=` +
			// Cookie value: Stops at unescaped ", ;, or whitespace. Allows \".
			`(?:[^;\s"\\]|\\.)+` +
			// Same pattern but preceded by a `; `
			`(?:\s*;\s*[^=\s;:]+=(?:[^;\s"\\]|\\.)+)*` +
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
		// m[0]:m[1] = full match (including preceding whitespace)
		// m[2]:m[3] = Group 1 ("Set-Cookie")
		// m[4]:m[5] = Group 2 (Cookie payload string)
		if len(m) < 6 {
			continue
		}

		// m[2] holds the exact starting byte index of "Set-Cookie" / "Cookie"
		headerPos := m[2]

		// Extract the byte slice for the second capture group (the actual cookies string)
		rawCookies := data[m[4]:m[5]]

		// Split the captured string by semicolons to evaluate each cookie
		for p := range bytes.SplitSeq(rawCookies, []byte(";")) {
			p = bytes.TrimSpace(p)
			if len(p) == 0 {
				continue
			}

			parts := bytes.SplitN(p, []byte("="), 2)
			if len(parts) != 2 {
				// Skip valueless cookies or Set-Cookie flags (e.g., Secure, HttpOnly)
				continue
			}

			// TODO: here check key names

			secrets = append(secrets, Cookie{
				Name:  string(parts[0]),
				Value: string(parts[1]),
			})

			// Use the exact position of "Set-Cookie" for all cookies found in this header
			pos = append(pos, headerPos)
		}
	}

	return secrets, pos
}

// MaxSecretLen returns the maximum length that a Cookie secret is expected to be
func (c *cookieDetector) MaxSecretLen() uint32 {
	return 1000
}
