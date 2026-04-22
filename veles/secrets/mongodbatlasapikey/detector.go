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

// Package mongodbatlasapikey contains a Veles Secret type and a Detector for
// MongoDB Atlas API Key pairs (public_api_key + private_api_key).
package mongodbatlasapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxElementLen is the maximum length of a single key element including context.
	maxElementLen = 120
	// maxDistance is the maximum distance between the public and private key in bytes.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// rePublicKey matches MongoDB Atlas public API keys with context labels.
// Public keys are alphanumeric strings, typically 8 characters long.
// Matches patterns like: public_api_key = "abcdefgh" or MONGODB_ATLAS_PUBLIC_KEY=abcdefgh
var rePublicKey = regexp.MustCompile(`(?i)(?:public[_-]?api[_-]?key|MONGODB[_-]?ATLAS[_-]?PUBLIC[_-]?KEY)\s*[=:]\s*["']?([a-z0-9]{8})(?:[^a-z0-9]|$)`)

// rePrivateKey matches MongoDB Atlas private API keys with context labels.
// Private keys are UUIDs.
// Matches patterns like: private_api_key = "12345678-abcd-1234-abcd-123456789012"
var rePrivateKey = regexp.MustCompile(`(?i)(?:private[_-]?api[_-]?key|MONGODB[_-]?ATLAS[_-]?PRIVATE[_-]?KEY)\s*[=:]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?`)

// NewDetector returns a context-aware detector that matches MongoDB Atlas API key
// pairs (public_api_key and private_api_key).
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxElementLen,
		MaxDistance:   maxDistance,
		FindA:         findAllMatches(rePublicKey),
		FindB:         findAllMatches(rePrivateKey),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return APIKey{PublicKey: string(p.A.Value), PrivateKey: string(p.B.Value)}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A == nil {
				return APIKey{PrivateKey: string(p.B.Value)}, true
			}
			return APIKey{PublicKey: string(p.A.Value)}, true
		},
	}
}

// findAllMatches returns a function which finds all matches of a given regex.
func findAllMatches(re *regexp.Regexp) func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		matches := re.FindAllSubmatchIndex(data, -1)
		var results []*pair.Match
		for _, m := range matches {
			results = append(results, &pair.Match{
				Start: m[0],
				Value: data[m[2]:m[3]],
			})
		}
		return results
	}
}
