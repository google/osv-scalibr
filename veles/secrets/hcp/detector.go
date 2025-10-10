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
	"strings"

	"github.com/google/osv-scalibr/veles"
	jwtlib "github.com/google/osv-scalibr/veles/secrets/common/jwt"
)

const (
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

// match holds the start offset and captured value of a regex match.
type match struct {
	start int
	value string
}

// findMatches returns the start offsets and captured group values for all matches of re in data.
func findMatches(re *regexp.Regexp, data []byte) []match {
	idxs := re.FindAllSubmatchIndex(data, -1)
	if len(idxs) == 0 {
		return nil
	}
	out := make([]match, 0, len(idxs))
	for _, m := range idxs {
		// m[0], m[1] are the full-match bounds; m[2], m[3] are the first capture group bounds
		out = append(out, match{start: m[2], value: string(data[m[2]:m[3]])})
	}
	return out
}

// pairWithinWindow pairs ids with the nearest subsequent secret within window bytes.
// Returns paired tuples and the leftover ids and secrets that could not be paired.
func pairWithinWindow(ids, secs []match, window int) (pairs [][2]match, leftoverIDs, leftoverSecs []match) {
	if len(ids) == 0 && len(secs) == 0 {
		return nil, nil, nil
	}
	usedSec := make([]bool, len(secs))
	j := 0
	for i := range ids {
		id := ids[i]
		// Advance to the first secret within [id.start-window, ...].
		// Pairing below uses absolute distance.
		for j < len(secs) && secs[j].start < id.start-window {
			j++
		}
		// Pair the nearest secret within [id.start-window, id.start+window]
		k := j
		for k < len(secs) && secs[k].start <= id.start+window {
			if abs(secs[k].start-id.start) <= window {
				pairs = append(pairs, [2]match{id, secs[k]})
				usedSec[k] = true
				k++
				break
			}
			k++
		}
		if k == j || (k > 0 && !usedSec[k-1]) { // nothing paired for this id
			leftoverIDs = append(leftoverIDs, id)
		}
	}
	for k := range secs {
		if !usedSec[k] {
			leftoverSecs = append(leftoverSecs, secs[k])
		}
	}
	return pairs, leftoverIDs, leftoverSecs
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// PairDetector finds HCP client credentials by key names and values.
// It emits pairs if both are present within a window, otherwise singletons.
type PairDetector struct{}

var _ veles.Detector = PairDetector{}

// NewPairDetector returns a Detector that finds HCP client credentials from key/value pairs.
func NewPairDetector() veles.Detector { return PairDetector{} }

// MaxSecretLen implements veles.Detector and returns the maximum input window
// size considered when pairing client id and secret values.
func (PairDetector) MaxSecretLen() uint32 { return maxPairWindowLen }

// Detect implements veles.Detector and emits ClientCredentials secrets based on
// presence of client_id and/or client_secret key/value pairs.
func (PairDetector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int

	ids := findMatches(reClientID, data)
	secs := findMatches(reClientSec, data)

	pairs, leftoversID, leftoversSec := pairWithinWindow(ids, secs, maxPairWindowLen)

	for _, p := range pairs {
		secrets = append(secrets, ClientCredentials{ClientID: p[0].value, ClientSecret: p[1].value})
		positions = append(positions, p[0].start)
	}
	for _, m := range leftoversID {
		secrets = append(secrets, ClientCredentials{ClientID: m.value})
		positions = append(positions, m.start)
	}
	for _, m := range leftoversSec {
		secrets = append(secrets, ClientCredentials{ClientSecret: m.value})
		positions = append(positions, m.start)
	}
	return secrets, positions
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
		for _, a := range normalizeAud(aud) {
			if a == "https://api.hashicorp.cloud" {
				audOK = true
				break
			}
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
