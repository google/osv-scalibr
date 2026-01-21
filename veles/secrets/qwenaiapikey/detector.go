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

package qwenaiapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxKeyLength is the maximum length of a valid Qwen AI API Key.
	// Standard keys are "sk-" followed by 32 hex chars, so 35 chars total.
	maxKeyLength = 40

	// maxDistance is the maximum distance between Qwen AI API Key and keywords
	// to be considered for pairing.
	maxDistance = 50
)

var (
	// tokenRe is a regular expression that matches Qwen AI API Keys.
	// Format: sk- followed by 32 lowercase hex/alphanumeric characters.
	// Example: sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c
	tokenRe = regexp.MustCompile(`\b(sk-[a-z0-9]{32})\b`)

	// keywordRe is a regular expression that matches Qwen/DashScope related keywords.
	keywordRe = regexp.MustCompile(`(?i)(qwen|dashscope|aliyun|apikey|sk-?sp)`)
)

// NewDetector returns a detector that matches Qwen AI keywords and API Key secret.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxKeyLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(tokenRe),
		FindB:         pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return QwenAIAPIKey{Key: string(p.A.Value)}, true
		},
	}
}
