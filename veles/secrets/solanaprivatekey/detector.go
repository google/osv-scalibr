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

package solanaprivatekey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxKeyLength is the maximum length of a Solana private key (Base58).
	maxKeyLength = 100
	// maxDistance is the maximum distance between the key and keywords.
	maxDistance = 50
)

var (
	// keyRe matches Base58 encoded Solana private keys (87-88 characters).
	keyRe = regexp.MustCompile(`[1-9A-HJ-NP-Za-km-z]{87,88}`)
	// keywordRe matches Solana-related keywords to reduce false positives.
	keywordRe = regexp.MustCompile(`(?i)(solana|phantom|sollet|secret_?key|private_?key|wallet|payer|keypair)`)
)

// NewDetector returns a detector for Solana private keys.
//
// This detector looks for Base58 strings (87-88 chars) and requires Solana-related
// keywords nearby to reduce false positives.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxKeyLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(keywordRe),
		FindB:         pair.FindAllMatches(keyRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return SolanaPrivateKey{Key: string(p.B.Value)}, true
		},
	}
}
