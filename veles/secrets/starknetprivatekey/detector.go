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

package starknetprivatekey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxKeyLength is the maximum length of a Starknet private key (Hex).
	maxKeyLength = 100
	// maxDistance is the maximum distance between the key and keywords.
	maxDistance = 50
)

var (
	// keyRe matches Hex encoded Starknet private keys (0x + 61-64 hex chars).
	keyRe = regexp.MustCompile(`0x[0-9a-fA-F]{61,64}`)
	// keywordRe matches Starknet-related keywords to reduce false positives.
	keywordRe = regexp.MustCompile(`(?i)(starknet|argent|braavos|secret_?key|private_?key|wallet|account|signer)`)
)

// NewDetector returns a detector for Starknet private keys.
//
// This detector looks for Hex strings starting with 0x and requires Starknet-related
// keywords nearby to reduce false positives.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxKeyLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(keywordRe),
		FindB:         pair.FindAllMatches(keyRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return StarknetPrivateKey{Key: string(p.B.Value)}, true
		},
	}
}
