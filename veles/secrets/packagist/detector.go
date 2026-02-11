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

package packagist

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewAPIKeyDetector()
	_ veles.Detector = NewAPISecretDetector()
	_ veles.Detector = NewOrgReadTokenDetector()
	_ veles.Detector = NewOrgUpdateTokenDetector()
	_ veles.Detector = NewUserUpdateTokenDetector()
	_ veles.Detector = NewConductorUpdateTokenDetector()
)

const (
	apiKeyMaxLen    = 50  // packagist_ack_ (14) + ~32 hex chars + padding
	apiSecretMaxLen = 100 // packagist_acs_ (14) + ~80 hex chars + padding
	tokenMaxLen     = 90  // packagist_xxx_ (14) + 68 hex chars + padding
	repoURLMaxLen   = 100 // https://repo.packagist.com + path
	usernameMaxLen  = 100 // reasonable username length
	// maxDistance is the maximum distance between API key and secret to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// apiKeyRe matches Packagist API Keys in the format:
// packagist_ack_[0-9a-f]{28,32}
// Based on observed format: 28-32 hex characters after prefix
var apiKeyRe = regexp.MustCompile(`packagist_ack_[0-9a-f]{28,32}`)

// apiSecretRe matches Packagist API Secrets in the format:
// packagist_acs_[0-9a-f]{64,96}
// Based on observed format: typically 80 hex characters after prefix
var apiSecretRe = regexp.MustCompile(`packagist_acs_[0-9a-f]{64,96}`)

// orgReadTokenRe matches Packagist Organization tokens with read-only access
var orgReadTokenRe = regexp.MustCompile(`packagist_ort_[0-9a-f]{68}`)

// orgUpdateTokenRe matches Packagist Organization tokens with update access
var orgUpdateTokenRe = regexp.MustCompile(`packagist_out_[0-9a-f]{68}`)

// userUpdateTokenRe matches Packagist User tokens with update access
var userUpdateTokenRe = regexp.MustCompile(`packagist_uut_[0-9a-f]{68}`)

// conductorUpdateTokenRe matches Packagist Conductor tokens with update access
var conductorUpdateTokenRe = regexp.MustCompile(`packagist_cut_[0-9a-f]{68}`)

// repoURLRe matches repo.packagist.com URLs
var repoURLRe = regexp.MustCompile(`https?://repo\.packagist\.com[/\w\-\.]*`)

// usernameRe matches username patterns with context (username, user, name keywords)
// The capture group extracts just the username value
var usernameRe = regexp.MustCompile(`(?i)\b(?:username|user|name)\b\s*[:=]?\s*([a-zA-Z0-9_\-]{3,50})\b`)

// NewAPIKeyDetector returns a detector for Packagist API Keys.
func NewAPIKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: apiKeyMaxLen,
		Re:     apiKeyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}

// NewAPISecretDetector returns a detector for Packagist API Secrets.
// This detector finds secrets along with their corresponding API Keys when both are found together.
// The Key field will be populated, enabling HMAC validation.
// Note: This detector requires BOTH key and secret to be present (within 10KB distance).
func NewAPISecretDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(apiKeyMaxLen, apiSecretMaxLen),
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(apiKeyRe),
		FindB:         pair.FindAllMatches(apiSecretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return APISecret{
				Secret: string(p.B.Value),
				Key:    string(p.A.Value),
			}, true
		},
	}
}

// NewOrgReadTokenDetector returns a detector for Packagist Organization tokens with read-only access.
// This detector finds tokens along with their corresponding repo URLs when both are found together.
func NewOrgReadTokenDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(tokenMaxLen, repoURLMaxLen),
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(orgReadTokenRe),
		FindB:         pair.FindAllMatches(repoURLRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return OrgReadToken{
				Token:   string(p.A.Value),
				RepoURL: string(p.B.Value),
			}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A != nil {
				return OrgReadToken{Token: string(p.A.Value)}, true
			}
			return nil, false
		},
	}
}

// NewOrgUpdateTokenDetector returns a detector for Packagist Organization tokens with update access.
// This detector finds tokens along with their corresponding repo URLs when both are found together.
func NewOrgUpdateTokenDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(tokenMaxLen, repoURLMaxLen),
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(orgUpdateTokenRe),
		FindB:         pair.FindAllMatches(repoURLRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return OrgUpdateToken{
				Token:   string(p.A.Value),
				RepoURL: string(p.B.Value),
			}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A != nil {
				return OrgUpdateToken{Token: string(p.A.Value)}, true
			}
			return nil, false
		},
	}
}

// NewUserUpdateTokenDetector returns a detector for Packagist User tokens with update access.
// This detector finds tokens along with their corresponding username and repo URLs.
// It uses ntuple to match all three elements: username, token, and repo URL.
func NewUserUpdateTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(usernameMaxLen, tokenMaxLen, repoURLMaxLen),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatchesGroup(usernameRe),
			ntuple.FindAllMatches(userUpdateTokenRe),
			ntuple.FindAllMatches(repoURLRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return UserUpdateToken{
				Username: string(ms[0].Value),
				Token:    string(ms[1].Value),
				RepoURL:  string(ms[2].Value),
			}, true
		},
		FromPartial: func(m ntuple.Match) (veles.Secret, bool) {
			// Only return partial match if it's the token (FinderIndex 1)
			if m.FinderIndex == 1 {
				return UserUpdateToken{Token: string(m.Value)}, true
			}
			return nil, false
		},
	}
}

// NewConductorUpdateTokenDetector returns a detector for Packagist Conductor tokens with update access.
// These tokens do not require validation.
func NewConductorUpdateTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: tokenMaxLen,
		Re:     conductorUpdateTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ConductorUpdateToken{Token: string(b)}, true
		},
	}
}
