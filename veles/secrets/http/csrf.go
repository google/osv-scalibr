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
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// preFilter is used to quickly check if the byte slice contains potential target keywords.
var preFilter = regexp.MustCompile(`(?i)(?:x-)?(?:csrf|xsrf)`)

var csrfPatterns = []*regexp.Regexp{
	// Quoted key value pairs (Logs, JSON, Configs, standard variables).
	//
	// Note: the value must be contained inside `'` or `"` to reduce false positive in case of a variable assignment in source code
	regexp.MustCompile(`(?i)(?:x[-_])?(?:csrf|xsrf)[-_]?(?:middleware)?[-_]?(?:token)?["']?\s*[:=]\s*["']([a-zA-Z0-9+/=_-]{16,128})["']`),

	// Unquoted HTTP Headers (HTTP dumps).
	regexp.MustCompile(`(?im)^(?:x[-_])?(?:csrf|xsrf)[-_]?(?:middleware)?[-_]?(?:token)?:\s+([a-zA-Z0-9+/=_-]{16,128})\b`),

	// HTML Tag: 'name' comes before 'value'.
	regexp.MustCompile(`(?i)<input[^>]+name=["'][\w-]*(?:csrf|xsrf)[\w-]*["'][^>]+value=["']([a-zA-Z0-9+/=_-]{16,128})["']`),

	// HTML Tag: 'value' comes before 'name'.
	regexp.MustCompile(`(?i)<input[^>]+value=["']([a-zA-Z0-9+/=_-]{16,128})["'][^>]+name=["'][\w-]*(?:csrf|xsrf)[\w-]*["']`),
}

// csrfTokenDetector scans file contents for hardcoded CSRF/XSRF tokens.
type csrfTokenDetector struct{}

// NewCSRFTokenDetector creates a new instance of the CSRFTokenDetector.
func NewCSRFTokenDetector() veles.Detector {
	return &csrfTokenDetector{}
}

// Detect scans the input byte slice for CSRF tokens using focused regex patterns.
func (d *csrfTokenDetector) Detect(data []byte) ([]veles.Secret, []int) {
	// Bypass full regex execution if the keywords aren't present at all.
	if !preFilter.Match(data) {
		return nil, nil
	}

	var secrets []veles.Secret
	var indices []int

	for _, pattern := range csrfPatterns {
		for _, match := range pattern.FindAllSubmatchIndex(data, -1) {
			if len(match) < 4 {
				continue
			}
			secrets = append(secrets, CSRFToken{
				Value: string(data[match[2]:match[3]]),
			})
			indices = append(indices, match[0])
		}
	}

	return secrets, indices
}

// MaxSecretLen defines the maximum expected token size.
func (d *csrfTokenDetector) MaxSecretLen() uint32 {
	return 300
}
