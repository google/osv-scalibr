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
	// maxTokenLength is the maximum length of a valid Discord Bot Token.
	// Discord Bot Tokens consist of three base64-encoded parts separated by dots:
	// - Bot user ID (variable length, typically 18-19 digits encoded)
	// - Timestamp (6 characters)
	// - HMAC signature (27+ characters)
	// Total length is typically around 60-75 characters.
	maxTokenLength = 80

	// maxDistance is the maximum distance between Discord Bot Token and Discord
	// keywords to be considered for pairing.
	maxDistance = 30
)

var (
	// tokenRe is a regular expression that matches Discord Bot Tokens.
	// Discord Bot Tokens have 3 parts separated by dots:
	// 1. Base64-encoded bot user ID (starts with M or N, 24+ chars)
	// 2. 6-character timestamp
	// 3. 27+ character HMAC signature
	// Reference: https://discord.com/developers/docs/reference#authentication
	tokenRe = regexp.MustCompile(`\b([MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,})\b`)

	// keywordRe is a regular expression that matches Discord related keywords.
	keywordRe = regexp.MustCompile(`(?i)(discord|bot[_\.\s-]?token|DISCORD_TOKEN)`)
)

// NewDetector returns a detector that matches Discord keyword and a Discord
// Bot Token secret.
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
