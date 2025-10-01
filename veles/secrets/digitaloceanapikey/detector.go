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

// Package digitaloceanapikey contains a Veles Secret type and a Detector for
// DigitalOcean API Tokens (prefix `dop_v1_`).
package digitaloceanapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a DigitalOcean API key.
const maxTokenLength = 71

// keyRe is a regular expression that matches a DigitalOcean API key.
// DigitalOcean API keys have the form: `dop_v1_` followed by 64
// alphanumeric characters.
var keyRe = regexp.MustCompile(`dop_v1_[abcdef0-9]{64}`)

// NewDetector returns a new simpletoken.Detector that matches
// DigitalOcean API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return DigitaloceanAPIToken{Key: string(b)}, true
		},
	}
}
