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

// Package pypiapitoken contains a Veles Secret type and a Detector for
// PyPI API Tokens (prefix `pypi-`).
package pypiapitoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a PyPI API Token.
const maxTokenLength = 150

// keyRe is a regular expression that matches a PyPI API Token.
// PyPI API Tokens have the form: `pypi-` followed by at least 85
// alphanumeric characters.
var keyRe = regexp.MustCompile(`pypi-[A-Za-z0-9-_]{85,}`)

// NewDetector returns a new simpletoken.Detector that matches
// PyPI API Tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return PyPIAPIToken{Token: string(b)}, true
		},
	}
}
