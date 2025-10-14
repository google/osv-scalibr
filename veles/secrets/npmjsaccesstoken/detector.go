// Copyright 2025 Google LLC
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

// Package npmjsaccesstoken contains a Veles Secret type and a Detector for
// npm.js Access Tokens (prefix `npm_`).
package npmjsaccesstoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of an npm.js access token.
const maxTokenLength = 40

// tokenRe is a regular expression that matches an npm.js access token.
// npm.js access tokens have the form: `npm_` followed by 36
// alphanumeric characters.
var tokenRe = regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)

// NewDetector returns a new simpletoken.Detector that matches
// npm.js access tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     tokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return NpmJSAccessToken{Token: string(b)}, true
		},
	}
}
