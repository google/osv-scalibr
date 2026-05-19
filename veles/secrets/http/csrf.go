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
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// csrfPattern matches CSRF tokens in HTTP dumps, HTML bodies, logs
	//
	// ref: https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection
	csrfPattern = regexp.MustCompile(
		`(?i)(?:csrf|xsrf)[a-z0-9_-]*(?:token)?["']?(?:\s+value\s*=\s*|\s*[:=]\s*)["']?([a-zA-Z0-9+\/=\-_]{16,128})`,
	)
)

// NewCSRFTokenDetector extract the CSRF token from the provided input
func NewCSRFTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: 1000,
		Re:     csrfPattern,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			matches := csrfPattern.FindSubmatch(b)
			if len(matches) < 2 {
				return nil, false
			}
			return CSRFToken{string(matches[1])}, true
		},
	}
}
