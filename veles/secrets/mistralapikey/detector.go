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

package mistralapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxKeyLength is the exact length of a Mistral API key.
	maxKeyLength = 32
	// maxDistance is the maximum distance between context and key.
	maxDistance = 200
)

var (
	// keyRe matches exactly 32 alphanumeric characters with word boundaries
	// to avoid matching parts of larger base64 blobs.
	keyRe = regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`)

	// contextRe matches Mistral-specific context indicators (case-insensitive).
	// Matches:
	// - mistral, Mistral, MISTRAL
	// - mistralai, MistralAI, mistral_ai, mistral-ai
	// - MistralKey, mistral_key, mistral-key
	// - MistralApiKey, mistral_api_key, mistral-api-key
	// - api.mistral.ai
	contextRe = regexp.MustCompile(`(?i)\bmistral(?:ai)?(?:[_-]?(?:api[_-]?)?key)?\b|api\.mistral\.ai`)
)

// NewDetector returns a new Detector that matches Mistral API keys.
// Since Mistral API keys are 32-character alphanumeric strings without a
// specific prefix, this detector requires context indicators (e.g., "mistral",
// "mistralai", "api.mistral.ai") within a nearby window to reduce false positives.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxKeyLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(contextRe),
		FindB:         pair.FindAllMatches(keyRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return MistralAPIKey{Key: string(p.B.Value)}, true
		},
	}
}
