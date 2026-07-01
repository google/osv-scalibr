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

// Package linearapikey contains a Veles Secret type and Detector for Linear API keys.
// Linear API keys use the ultra-specific prefix "lin_api_" followed by 40 alphanumeric characters,
// making this a very low false-positive detector.
package linearapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure the constructor satisfies the interface at compile time.
	_ veles.Detector = NewDetector()
)

// Linear API keys are exactly 48 characters: lin_api_ (8 chars) + 40 alphanumeric chars
const maxKeyLen = 48

var keyRe = regexp.MustCompile(`lin_api_[A-Za-z0-9]{40}\b`)

// NewDetector returns a detector for Linear API keys (lin_api_xxxxxxxx...).
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxKeyLen,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}

// APIKey represents a Linear API key.
type APIKey struct {
	Key string
}
