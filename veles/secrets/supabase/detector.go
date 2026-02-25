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

package supabase

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewPATDetector()
	_ veles.Detector = NewProjectSecretKeyDetector()
	_ veles.Detector = NewServiceRoleJWTDetector()
)

const (
	patMaxLen              = 44   // sbp_ (4) + 40 hex chars
	projectSecretKeyMaxLen = 46   // sb_secret_ (10) + 36 chars
	projectRefMaxLen       = 50   // project ref is typically 20 chars
	serviceRoleJWTMaxLen   = 1000 // JWT tokens can be quite long
	// maxDistance is the maximum distance between project ref and secret key to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// patRe matches Supabase Personal Access Tokens in the format:
// `sbp_` followed by 40 hexadecimal characters.
// Reference : https://supabase.com/docs/reference/api/introduction#authentication
var patRe = regexp.MustCompile(`sbp_[a-f0-9]{40}`)

// projectSecretKeyRe matches Supabase Project Secret Keys in the format:
// `sb_secret_` followed by 31-36 base64url characters.
// Reference : https://supabase.com/docs/guides/api/api-keys#overview
var projectSecretKeyRe = regexp.MustCompile(`sb_secret_[A-Za-z0-9_-]{31,36}`)

// projectRefRe matches Supabase project references in URLs.
// Format: `https://` followed by a 20-character lowercase alphanumeric
// project reference, then `.supabase.co`.
// Reference : https://supabase.com/docs/guides/auth/jwts
var projectRefRe = regexp.MustCompile(`https://([a-z0-9]{20})\.supabase\.co`)

// jwtRe matches JWT tokens (three base64url segments separated by dots).
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// jwtPayload represents the decoded JWT payload.
type jwtPayload struct {
	Iss  string `json:"iss"`
	Role string `json:"role"`
}

// NewPATDetector returns a new simpletoken.Detector that matches
// Supabase Personal Access Tokens. These tokens are used to authenticate
// with the Supabase Management API.
func NewPATDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: patMaxLen,
		Re:     patRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return PAT{Token: string(b)}, true
		},
	}
}

// FindAllProjectRef returns a function which finds all project references
// in Supabase URLs. It extracts the 20-character project reference from
// the capture group in the regex match.
func FindAllProjectRef() func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		matches := projectRefRe.FindAllSubmatchIndex(data, -1)
		var results []*pair.Match
		for _, m := range matches {
			// m[0], m[1] = full match positions
			// m[2], m[3] = first capture group positions (the project ref)
			if len(m) >= 4 {
				results = append(results, &pair.Match{
					Start: m[0],            // Use the full match start position
					Value: data[m[2]:m[3]], // Extract the captured project ref
				})
			}
		}
		return results
	}
}

// NewProjectSecretKeyDetector returns a new pair.Detector that matches
// Supabase Project Secret Keys along with their corresponding project
// references. This detector finds secret keys and project references when
// both are found together within 10KB distance. The ProjectRef field will
// be populated, enabling validation against the project-specific endpoint.
// Note: This detector requires BOTH project ref and secret key to be present.
func NewProjectSecretKeyDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(projectRefMaxLen, projectSecretKeyMaxLen),
		MaxDistance:   maxDistance,
		FindA:         FindAllProjectRef(),
		FindB:         pair.FindAllMatches(projectSecretKeyRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return ProjectSecretKey{
				Key:        string(p.B.Value),
				ProjectRef: string(p.A.Value),
			}, true
		},
	}
}

// NewServiceRoleJWTDetector returns a new simpletoken.Detector that matches
// Supabase service_role JWT tokens. This detector validates that the JWT
// has `iss="supabase"` and `role="service_role"` in its payload. Service
// role JWTs are long-lived tokens with unrestricted privileges that bypass
// Row Level Security (RLS).
func NewServiceRoleJWTDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: serviceRoleJWTMaxLen,
		Re:     jwtRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			token := string(b)

			// Split JWT into parts
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				return nil, false
			}

			// Decode the payload (second part)
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, false
			}

			// Parse JSON payload
			var claims jwtPayload
			if err := json.Unmarshal(payload, &claims); err != nil {
				return nil, false
			}

			// Validate that it's a Supabase service_role JWT
			if claims.Iss != "supabase" || claims.Role != "service_role" {
				return nil, false
			}

			return ServiceRoleJWT{Token: token}, true
		},
	}
}
