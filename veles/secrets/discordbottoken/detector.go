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

package discordbottoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxTokenLength is the maximum length of a Discord bot token.
	// Standard tokens are ~59 chars, MFA tokens can be longer but usually stay within a reasonable bound.
	maxTokenLength = 100
	// maxDistance is the maximum distance between the token and keywords.
	maxDistance = 50
)

var (
	// tokenRe matches both standard and MFA Discord bot tokens.
	tokenRe = regexp.MustCompile(`(?i)\b([MN][A-Za-z\d_-]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}|mfa\.[A-Za-z\d_-]{20,})\b`)
	// keywordRe matches Discord-related keywords to reduce false positives.
	keywordRe = regexp.MustCompile(`(?i)(discord|bot|token|client|authorization)`)
)

// NewDetector returns a detector that finds Discord bot tokens near relevant keywords.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxTokenLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(tokenRe),
		FindB:         pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return DiscordBotToken{Token: string(p.A.Value)}, true
		},
	}
}
