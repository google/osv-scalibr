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

package gitlab

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

var (
	// Ensure constructor satisfies the interface at compile time.
	_ veles.Detector = NewFeatureFlagsClientTokenDetector()
)

const (
	// maxFFTokenLength is the maximum length of a GitLab Feature Flags Client Token
	maxFFTokenLength = 100
	// maxFFEndpointLength is the maximum length of a Feature Flags endpoint URL
	maxFFEndpointLength = 500
	// maxFFDistance is the maximum distance between elements to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxFFDistance = 10 * 1 << 10 // 10 KiB
)

// ffTokenRe matches GitLab Feature Flags Client Tokens starting with glffct- followed by alphanumeric, underscores, and hyphens
// Example: glffct-KH5TUFTqs5ysYsDxPz24, glffct-wwGhXf4qa_VYq7oHC7Xy
var ffTokenRe = regexp.MustCompile(`glffct-[A-Za-z0-9_-]{15,}`)

// ffEndpointRe matches GitLab Feature Flags Unleash API endpoints
// Examples: https://gitlab.com/api/v4/feature_flags/unleash/79858780
var ffEndpointRe = regexp.MustCompile(`https?://[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]/api/v4/feature_flags/unleash/\d+`)

// NewFeatureFlagsClientTokenDetector returns a new Detector that matches GitLab Feature Flags Client Tokens.
// It uses pair detection to find token and endpoint URL pairs.
// When both are found together, it returns a complete FeatureFlagsClientToken.
// When only the token is found, it returns FeatureFlagsClientToken with only the token field.
func NewFeatureFlagsClientTokenDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxFFTokenLength, maxFFEndpointLength),
		MaxDistance:   maxFFDistance,
		FindA:         pair.FindAllMatches(ffTokenRe),
		FindB:         pair.FindAllMatches(ffEndpointRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return FeatureFlagsClientToken{
				Token:    string(p.A.Value),
				Endpoint: string(p.B.Value),
			}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			// Only return partial match if it's the token (A)
			if p.A != nil {
				return FeatureFlagsClientToken{Token: string(p.A.Value)}, true
			}
			return nil, false
		},
	}
}
