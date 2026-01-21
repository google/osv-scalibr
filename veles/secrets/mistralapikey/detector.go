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
)

const (
	// keyLength is the exact length of a Mistral API key.
	keyLength = 32
	// contextWindow is the number of bytes around a potential key to search for
	// context indicators.
	contextWindow = 200
)

var (
	// Ensure the detector satisfies the interface at compile time.
	_ veles.Detector = (*detector)(nil)

	// keyRe matches exactly 32 alphanumeric characters with word boundaries
	// to avoid matching parts of larger base64 blobs.
	keyRe = regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`)

	// contextRe matches Mistral-specific context indicators (case-insensitive).
	// These are used to reduce false positives since Mistral keys don't have
	// a distinguishing prefix. Uses word boundaries to avoid matching "mistral"
	// as part of a larger word like "amistralb".
	contextRe = regexp.MustCompile(`(?i)\bmistral(?:ai|_api_key)?\b|api\.mistral\.ai`)
)

// detector implements context-aware detection for Mistral API keys.
type detector struct{}

// NewDetector returns a new Detector that matches Mistral API keys.
// Since Mistral API keys are 32-character alphanumeric strings without a
// specific prefix, this detector requires context indicators (e.g., "mistral",
// "mistralai", "api.mistral.ai") within a nearby window to reduce false positives.
func NewDetector() veles.Detector {
	return &detector{}
}

// MaxSecretLen returns the maximum length of secrets this detector can find.
func (d *detector) MaxSecretLen() uint32 {
	return keyLength
}

// Detect finds potential Mistral API keys that have contextual indicators nearby.
func (d *detector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int

	matches := keyRe.FindAllIndex(data, -1)
	for _, match := range matches {
		start, end := match[0], match[1]

		// Determine the context window boundaries.
		contextStart := start - contextWindow
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := end + contextWindow
		if contextEnd > len(data) {
			contextEnd = len(data)
		}

		// Check if there's Mistral-related context nearby.
		contextData := data[contextStart:contextEnd]
		if contextRe.Match(contextData) {
			key := string(data[start:end])
			secrets = append(secrets, MistralAPIKey{Key: key})
			positions = append(positions, start)
		}
	}

	return secrets, positions
}
