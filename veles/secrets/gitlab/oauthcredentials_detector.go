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
	_ veles.Detector = NewOAuthCredentialsDetector()
)

const (
	// maxClientIDLength is the maximum length of a GitLab OAuth client_id (64 hex chars)
	maxClientIDLength = 64
	// maxClientSecretLength is the maximum length of a GitLab OAuth client_secret
	// Format: gloas- prefix + 64 hex chars = ~70 chars
	maxClientSecretLength = 100
	// maxHostnameLength is the maximum length of a hostname
	maxHostnameLength = 300
	// maxDistance is the maximum distance between elements to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// clientSecretRe matches GitLab OAuth client_secret starting with gloas- followed by 64 hex characters
var clientSecretRe = regexp.MustCompile(`gloas-[a-f0-9]{64}`)

// clientIDRe matches GitLab OAuth client_id in two formats:
//  1. Standalone: 64 hexadecimal characters (0-9, a-f)
//  2. Context-aware: key-value patterns like client_id: value, client_id=value, or client_id="value"
//     Uses capture group to extract only the 64-char hex value
var clientIDRe = regexp.MustCompile(`(?:(?i:client[_-]?id)["']?\s*[=:]\s*["']?)?([a-f0-9]{64})`)

// hostnameRe matches GitLab hostnames in URLs (gitlab.com or self-hosted instances)
// Examples: https://gitlab.com, https://gitlab.example.com, http://localhost:8080
var hostnameRe = regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](?::\d+)?)`)

// NewOAuthCredentialsDetector returns a new Detector that matches GitLab OAuth credentials.
// It uses ntuple detection to find client_secret, client_id, and hostname.
// When all three are found together, it returns complete OAuthCredentials.
// When only client_secret and client_id are found, it returns OAuthCredentials with empty hostname (defaults to gitlab.com).
func NewOAuthCredentialsDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxClientSecretLength, maxClientIDLength, maxHostnameLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(clientSecretRe),
			ntuple.FindAllMatchesGroup(clientIDRe),
			ntuple.FindAllMatches(hostnameRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return OAuthCredentials{
				ClientSecret: string(ms[0].Value),
				ClientID:     string(ms[1].Value),
				Hostname:     string(ms[2].Value),
			}, true
		},
		FromPartial: func(m ntuple.Match) (veles.Secret, bool) {
			// Only return partial match if it's the client_secret (FinderIndex 0)
			if m.FinderIndex == 0 {
				return OAuthCredentials{ClientSecret: string(m.Value)}, true
			}
			return nil, false
		},
	}
}
