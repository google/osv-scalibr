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

package bip39mnemonic

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxPhraseLength is the maximum length of a 24-word mnemonic phrase.
	maxPhraseLength = 512
	// maxDistance is the maximum distance between the phrase and keywords.
	maxDistance = 50
)

var (
	// phraseRe matches 12 to 24 lowercase words (3+ chars each) separated by spaces or newlines.
	phraseRe = regexp.MustCompile(`(?i)\b[a-z]{3,}(\s+[a-z]{3,}){11,23}\b`)
	// keywordRe matches mnemonic-related keywords.
	keywordRe = regexp.MustCompile(`(?i)(mnemonic|seed_?phrase|recovery_?phrase|secret_?phrase|bip39|wallet)`)
)

// NewDetector returns a detector for BIP39 mnemonic phrases.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxPhraseLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(keywordRe),
		FindB:         pair.FindAllMatches(phraseRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return BIP39Mnemonic{Phrase: string(p.B.Value)}, true
		},
	}
}
