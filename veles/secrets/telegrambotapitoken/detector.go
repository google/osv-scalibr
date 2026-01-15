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

package telegrambotapitoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxTokenLength is the maximum length of a valid Telegram Bot API token.
	// it consists of 8-10 digits followed by a :, the : is followed by a 35 character Telegram internal identifier/hash
	// Ref: https://stackoverflow.com/questions/61868770/tegram-bot-api-token-format
	maxTokenLength = 46

	// maxDistance is the maximum distance between Telegram Bot API token and Telegram keywords to be considered for pairing (repurposed for finding close keywords that might show it is a Telegram Bot API token).
	// 20 is a good upper bound as we want to search for near keywords.
	maxDistance = 20
)

var (
	// tokenRe is a regular expression that matches Telegram Bot API token.
	// Official format reference is:
	// - https://core.telegram.org/bots/api#authorizing-your-bot
	// Other references that explain the format
	// - https://stackoverflow.com/questions/61868770/tegram-bot-api-token-format
	tokenRe = regexp.MustCompile(`\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b`)

	// keywordRe is a regular expression that matches Telegram related keywords.
	keywordRe = regexp.MustCompile(`(?i)(telegram|tgram)`)
)

// NewDetector returns a detector that matches Telegram keyword, and a Telegram Bot API secret.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxTokenLength, MaxDistance: maxDistance,
		FindA: pair.FindAllMatches(tokenRe),
		FindB: pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return TelegramBotAPIToken{Token: string(p.A.Value)}, true
		},
	}
}
