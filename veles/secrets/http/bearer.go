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
	// bearerPattern matches Bearer Authorization in HTTP dumps, flat JSON, and
	// import/export "collection" formats (Postman, Insomnia, OpenAPI, Bruno, etc.).
	//
	// ref: https://datatracker.ietf.org/doc/html/rfc7235
	bearerPattern = regexp.MustCompile(
		`(?is)` +
			`\bAuthorization` +
			// Delimiters (handles HTTP/flat formats)
			`["'\s=:]{0,10}` +
			// Optional nearby "value" key (handles JSON/YAML)
			`(?:.{0,150}?\bvalue["'\s=:]*)?` +
			`Bearer\s+([A-Za-z0-9\-\._~+/=]+)`,
	)
)

// NewBearerDetector extract the Bearer token from the provided input
func NewBearerDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: 8 * veles.KiB,
		Re:     bearerPattern,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			matches := bearerPattern.FindSubmatch(b)
			if len(matches) < 2 {
				return nil, false
			}
			return BearerToken{string(matches[1])}, true
		},
	}
}
