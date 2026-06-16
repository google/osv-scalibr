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
		`(?i)(?:^|[^\w-])(?:Set-)?Cookie\s*:\s*` +
			`(` +
			// Cookie name
			`[^=\s;:]+` +
			// Equal sign
			`=` +
			// Cookie value
			`[^;\s]+` +
			// Same pattern but preceded by a `; `
			`(?:\s*;\s*[^=\s;:]+=[^;\s]+)*` +
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
		// Ensure the match actually contains our capture group (needs at least 4 indices)
		if len(m) < 4 {
			continue
		}

		// Extract the byte slice for the first capture group (the actual cookies string)
		rawCookies := data[m[2]:m[3]]

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

			secrets = append(secrets, Cookie{
				Name:  string(parts[0]),
				Value: string(parts[1]),
			})
			pos = append(pos, m[0])
		}
	}

	return secrets, pos
}

// MaxSecretLen returns the maximum length that a Cookie secret is expected to be
func (c *cookieDetector) MaxSecretLen() uint32 {
	return 1000
}
