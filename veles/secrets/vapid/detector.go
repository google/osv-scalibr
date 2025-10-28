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
	// maxPairWindowLen is the maximum window length to pair env-style credentials.
	maxPairWindowLen = 10 * 1 << 10 // 10 KiB
)

var (
	publicKeyPattern  = regexp.MustCompile(`[A-Za-z0-9_-]{87}`)
	privateKeyPattern = regexp.MustCompile(`[A-Za-z0-9_-]{43}`)
)

func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxLen: maxPairWindowLen,
		FindA:  pair.FindAllMatches(publicKeyPattern),
		FindB:  pair.FindAllMatches(privateKeyPattern),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			pubB64, privB64 := p.A.Value, p.B.Value
			ok, _ := validateVAPIDKeys(pubB64, privB64)
			if !ok {
				return nil, false
			}
			return Keys{
				PublicB64:  pubB64,
				PrivateB64: privB64,
			}, true
		},
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
