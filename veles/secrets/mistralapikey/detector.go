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

package mistralapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxKeyLength is the maximum length of a valid Mistral API Key.
	maxKeyLength = 40

	// maxDistance is the maximum distance between Mistral API Key and keywords
	// to be considered for pairing.
	maxDistance = 50
)

var (
	// tokenRe is a regular expression that matches Mistral API Keys.
	// Format: Typically 32 characters, alphanumeric.
	tokenRe = regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`)

	// keywordRe is a regular expression that matches Mistral related keywords.
	keywordRe = regexp.MustCompile(`(?i)(mistral|mistral_api)`)
)

// NewDetector returns a detector that matches Mistral keywords and API Key secret.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxKeyLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(tokenRe),
		FindB:         pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return MistralAPIKey{Key: string(p.A.Value)}, true
		},
	}
}
