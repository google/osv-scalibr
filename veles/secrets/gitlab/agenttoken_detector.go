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
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

var (
	// Ensure constructor satisfies the interface at compile time.
	_ veles.Detector = NewAgentTokenDetector()
)

const (
	// maxAgentTokenLength is the maximum length of a GitLab Agent Token
	maxAgentTokenLength = 100
	// maxKasURLLength is the maximum length of a KAS URL
	maxKasURLLength = 500
	// maxAgentDistance is the maximum distance between elements to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxAgentDistance = 10 * 1 << 10 // 10 KiB
)

// agentTokenRe matches GitLab Agent Tokens starting with glagent- followed by alphanumeric, underscore, dash, and dot characters
// Example: glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr
var agentTokenRe = regexp.MustCompile(`glagent-[0-9a-zA-Z_\-\.]{50,}`)

// kasURLRe matches KAS (Kubernetes Agent Server) WebSocket URLs that start with kas.
// Examples: wss://kas.gitlab.com, wss://kas.gitlab.example.com:8080
var kasURLRe = regexp.MustCompile(`wss://kas\.[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](?::[0-9]+)?(?:/[^\s]*)?`)

// NewAgentTokenDetector returns a new Detector that matches GitLab Agent Tokens.
// It uses ntuple detection to find token and KAS URL.
// When both are found together, it returns a complete AgentToken.
// When only the token is found, it returns AgentToken with only the token field.
func NewAgentTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxAgentTokenLength, maxKasURLLength),
		MaxDistance:   maxAgentDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(agentTokenRe),
			ntuple.FindAllMatches(kasURLRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return AgentToken{
				Token:  string(ms[0].Value),
				KasURL: string(ms[1].Value),
			}, true
		},
		FromPartial: func(m ntuple.Match) (veles.Secret, bool) {
			// Only return partial match if it's the token (FinderIndex 0)
			if m.FinderIndex == 0 {
				return AgentToken{Token: string(m.Value)}, true
			}
			return nil, false
		},
	}
}
