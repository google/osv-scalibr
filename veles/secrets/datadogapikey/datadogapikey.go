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

// Package datadogapikey contains a Veles Secret type and Detector for Datadog API keys.
// Datadog API keys are 32-character hexadecimal strings. Because a raw 32-hex regex
// would be catastrophically noisy (matches MD5, UUID segments, commit hashes), this
// detector uses the keyword-gated pair.Detector pattern to require a Datadog-specific
// keyword near the token.
package datadogapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxTokenLength is the maximum length of a Datadog API key (32 hex chars).
	maxTokenLength = 32

	// maxDistance is the maximum distance between the keyword and the token value.
	maxDistance = 20
)

var (
	// keywordRe matches Datadog-related context keywords (case-insensitive),
	// optionally surrounded by quotes, followed by a separator (= or :).
	keywordRe = regexp.MustCompile(
		`(?i)["']?\b(?:DATADOG_API_KEY|DD_API_KEY|DATADOG_API_TOKEN|DD_API_TOKEN|DATADOG_TOKEN|DD_TOKEN)\b["']?\s*[=:]`,
	)

	// tokenRe matches a 32-character hexadecimal string.
	apiKeyRe = regexp.MustCompile(`\b[a-f0-9]{32}\b`)
)

var _ veles.Detector = NewDetector()

// NewDetector returns a new Detector that matches Datadog API keys by finding a keyword-token pair.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxTokenLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(keywordRe),
		FindB:         pair.FindAllMatches(apiKeyRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return APIKey{Key: string(p.B.Value)}, true
		},
	}
}

// APIKey represents a Datadog API key.
type APIKey struct {
	Key string
}
