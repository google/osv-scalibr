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

package supabase

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/jwt"
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
	patMaxLen              = 44 // sbp_ (4) + 40 hex chars
	projectSecretKeyMaxLen = 46 // sb_secret_ (10) + 36 chars
	projectRefMaxLen       = 50 // project ref is typically 20 chars
	// maxDistance is the maximum distance between project ref and secret key to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// patRe matches Supabase Personal Access Tokens in the format:
// sbp_[a-f0-9]{40}
var patRe = regexp.MustCompile(`sbp_[a-f0-9]{40}`)

// projectSecretKeyRe matches Supabase Project Secret Keys in the format:
// sb_secret_[A-Za-z0-9_-]{31,36}
var projectSecretKeyRe = regexp.MustCompile(`sb_secret_[A-Za-z0-9_-]{31,36}`)

// projectRefRe matches Supabase project references in URLs.
// Format: https://<project-ref>.supabase.co
var projectRefRe = regexp.MustCompile(`https://([a-z0-9]{20})\.supabase\.co`)

// NewPATDetector returns a detector for Supabase Personal Access Tokens.
func NewPATDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: patMaxLen,
		Re:     patRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return PAT{Token: string(b)}, true
		},
	}
}

// NewProjectSecretKeyDetector returns a detector for Supabase Project Secret Keys.
// This detector finds secret keys along with their corresponding project references when both are found together.
// The ProjectRef field will be populated, enabling validation against the project-specific endpoint.
// Note: This detector requires BOTH project ref and secret key to be present (within 10KB distance).
func NewProjectSecretKeyDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(projectRefMaxLen, projectSecretKeyMaxLen),
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(projectRefRe),
		FindB:         pair.FindAllMatches(projectSecretKeyRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			// Extract project ref from the URL match
			matches := projectRefRe.FindSubmatch(p.A.Value)
			if len(matches) < 2 {
				return nil, false
			}
			projectRef := string(matches[1])

			return ProjectSecretKey{
				Key:        string(p.B.Value),
				ProjectRef: projectRef,
			}, true
		},
	}
}

type serviceRoleJWTDetector struct{}

// NewServiceRoleJWTDetector returns a detector for Supabase service_role JWT tokens.
// This detector validates that the JWT has iss="supabase" and role="service_role".
func NewServiceRoleJWTDetector() veles.Detector {
	return &serviceRoleJWTDetector{}
}

// Detect finds Supabase service_role JWT tokens.
func (d *serviceRoleJWTDetector) Detect(data []byte) ([]veles.Secret, []int) {
	tokens, positions := jwt.ExtractTokens(data)
	var secrets []veles.Secret
	var secretPositions []int

	for i, token := range tokens {
		payload := token.Payload()

		// Validate that it's a Supabase service_role JWT
		iss, issOk := payload["iss"].(string)
		role, roleOk := payload["role"].(string)
		if !issOk || !roleOk || iss != "supabase" || role != "service_role" {
			continue
		}

		secrets = append(secrets, ServiceRoleJWT{Token: token.Raw()})
		secretPositions = append(secretPositions, positions[i])
	}

	return secrets, secretPositions
}

// MaxSecretLen returns the maximum length of a JWT token.
func (d *serviceRoleJWTDetector) MaxSecretLen() uint32 {
	return jwt.MaxTokenLength
}
