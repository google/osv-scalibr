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

package hcp

import (
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/veles"
	jwtlib "github.com/google/osv-scalibr/veles/secrets/common/jwt"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxSecretLen is a broad upper bound of the maximum length that hcp_client_id and hcp_client_secret can have
	maxSecretLen = 80
	// maxPairWindowLen is the maximum window length to pair env-style credentials.
	maxPairWindowLen = 10 * 1 << 10 // 10 KiB
	// maxAccessTokenLen is the maximum length of a JWT token (delegated to common jwt limits).
	maxAccessTokenLen = jwtlib.MaxTokenLength
)

var (
	// reClientID is a regular expression that matches HCP client IDs from env vars or strings.
	reClientID = regexp.MustCompile(`["']?\b(?:HCP_CLIENT_ID|hcp_client_id)\b["']?\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?`)
	// reClientSec is a regular expression that matches HCP client secrets from env vars or strings.
	reClientSec = regexp.MustCompile(`["']?\b(?:HCP_CLIENT_SECRET|hcp_client_secret)\b["']?\s*[:=]\s*["']?([A-Za-z0-9._~\-]{64})["']?`)
)

// NewPairDetector returns a Detector that finds HCP client credentials from key/value pairs.
func NewPairDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxSecretLen, MaxDistance: maxPairWindowLen,
		FindA: findMatches(reClientID), FindB: findMatches(reClientSec),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return ClientCredentials{ClientID: p.A.Value, ClientSecret: p.B.Value}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A == nil {
				return ClientCredentials{ClientSecret: p.B.Value}, true
			}
			return ClientCredentials{ClientID: p.A.Value}, true
		},
	}
}

// findMatches returns the start offsets and captured group values for all matches of re in data.
func findMatches(re *regexp.Regexp) func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		idxs := re.FindAllSubmatchIndex(data, -1)
		if len(idxs) == 0 {
			return nil
		}
		out := make([]*pair.Match, 0, len(idxs))
		for _, m := range idxs {
			// m[0], m[1] are the full-match bounds; m[2], m[3] are the first capture group bounds
			out = append(out, &pair.Match{Position: m[2], Value: string(data[m[2]:m[3]])})
		}
		return out
	}
}

// AccessTokenDetector finds HCP access tokens by scanning for JWTs and checking
// JWT payload for HashiCorp issuer/audience hints.
type AccessTokenDetector struct{}

var _ veles.Detector = AccessTokenDetector{}

// NewAccessTokenDetector returns a Detector that finds HCP access tokens from JWTs.
func NewAccessTokenDetector() veles.Detector { return AccessTokenDetector{} }

// MaxSecretLen implements veles.Detector and returns the maximum size of an
// access token that the detector accounts for.
func (AccessTokenDetector) MaxSecretLen() uint32 { return maxAccessTokenLen }

// Detect implements veles.Detector and returns AccessToken secrets for JWTs
// whose payload looks like HCP.
func (AccessTokenDetector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int
	tokens, poss := jwtlib.ExtractTokens(data)
	for i, t := range tokens {
		if isHCPAccessToken(t) {
			secrets = append(secrets, AccessToken{Token: t.Raw()})
			positions = append(positions, poss[i])
		}
	}
	return secrets, positions
}

// isHCPAccessToken decodes the JWT header and payload and checks issuer/audience hints
// consistent with HashiCorp Cloud Platform.
func isHCPAccessToken(t jwtlib.Token) bool {
	hdr := t.Header()
	if typ, ok := hdr["typ"].(string); ok && !strings.EqualFold(typ, "JWT") {
		return false
	}
	p := t.Payload()
	iss, _ := p["iss"].(string)
	if iss != "https://auth.idp.hashicorp.com/" {
		return false
	}
	audOK := false
	if aud, ok := p["aud"]; ok {
		if slices.Contains(normalizeAud(aud), "https://api.hashicorp.cloud") {
			audOK = true
		}
	}
	if !audOK {
		return false
	}
	if gty, ok := p["gty"].(string); !ok || gty != "client-credentials" {
		return false
	}
	return true
}

func normalizeAud(a any) []string {
	switch v := a.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
