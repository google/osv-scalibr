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

package vapid

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	publicKeyLen  = 87
	privateKeyLen = 43
	maxKeyLen     = max(publicKeyLen, privateKeyLen)

	// maxDistance is the maximum window length to pair env-style credentials.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	// match a base64 blob of exactly 87 characters
	publicKeyPattern = regexp.MustCompile(`\b([A-Za-z0-9_-]{87})\b`)
	// match a base64 blob of exactly 43 characters
	privateKeyPattern = regexp.MustCompile(`\b([A-Za-z0-9_-]{43})\b`)
)

// NewDetector returns a VAPID private key detector
//
// a key is detected if:
//
// - it has some context, (ex: `VAPID_KEY:base64blob`)
// - it is validated against a nearby public key
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxKeyLen, MaxDistance: maxDistance,
		FindA: findStrict(publicKeyPattern),
		FindB: findStrict(privateKeyPattern),
		FromPair: func(data []byte, p pair.Pair) (veles.Secret, bool) {
			pubB64, privB64 := p.A.Value(data), p.B.Value(data)
			if ok, _ := validateVAPIDKeys(pubB64, privB64); !ok {
				return nil, false
			}
			return Key{PublicB64: pubB64, PrivateB64: privB64}, true
		},
	}
}

// findStrict returns all matches found using a "strict" regex.
//
// A "strict" regex must be composed by a single capture group for the payload,
// and non-capturing groups for the boundaries, e.g.:
// `\b([group]{len})\b`
func findStrict(re *regexp.Regexp) func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		matches := re.FindAllSubmatchIndex(data, -1)
		var results []*pair.Match
		for _, m := range matches {
			results = append(results, &pair.Match{
				End:   m[3],
				Start: m[2],
			})
		}
		return results
	}
}

// validateVAPIDKeys checks if a VAPID public key matches a private key (P-256)
func validateVAPIDKeys(pubB64, privB64 string) (bool, error) {
	// Decode base64url keys
	pubBytes, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}
	privBytes, err := base64.RawURLEncoding.DecodeString(privB64)
	if err != nil {
		return false, fmt.Errorf("invalid private key: %w", err)
	}

	// Load curve
	curve := ecdh.P256()

	// Parse keys
	pubKey, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	privKey, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Compare public keys
	expectedPub := privKey.PublicKey()
	if !expectedPub.Equal(pubKey) {
		return false, nil
	}

	return true, nil
}
