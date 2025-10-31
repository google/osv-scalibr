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
	maxSecretLen = 87
	// maxDistance is the maximum window length to pair env-style credentials.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	publicKeyPattern = regexp.MustCompile(`[A-Za-z0-9_-]{87}`)
	// match:
	// - **vapid**=base64blob with exact length of 43
	// - **vapid**"="base64blob with exact length of 43
	// - base64blob with exact length of 43
	privateKeyPattern = regexp.MustCompile(`(?i)(vapid\S*)?[ \t:=]+["']?([A-Za-z0-9_-]{43})([^A-Za-z0-9_-]|$)`)
)

// NewDetector returns a VAPID private key detector
//
// a key is detected if:
//
// - it has some context, (ex: `VAPID_KEY:base64blob`)
// - it is validated against a nearby public key
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxSecretLen, MaxDistance: maxDistance,
		FindA: pair.FindAllMatches(publicKeyPattern),
		FindB: findAllMatchesWithContext(privateKeyPattern),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			pubB64, privB64 := p.A.Value, p.B.Value
			if ok, _ := validateVAPIDKeys(pubB64, privB64); !ok {
				return nil, false
			}
			return Keys{PublicB64: pubB64, PrivateB64: privB64}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.B == nil || !p.B.HasContext {
				return nil, false
			}
			return Keys{PrivateB64: p.B.Value}, true
		},
	}
}

// findAllMatchesWithContext returns a function which finds all matches of a given regex
// and adds metadata to the Match depending if it found context before the match
func findAllMatchesWithContext(re *regexp.Regexp) func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		matches := re.FindAllSubmatchIndex(data, -1)
		var results []*pair.Match
		for _, m := range matches {
			fmt.Println(m)
			hasVapid := m[2] != -1
			results = append(results, &pair.Match{
				Value:      string(data[m[4]:m[5]]),
				Position:   m[0],
				HasContext: hasVapid,
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
