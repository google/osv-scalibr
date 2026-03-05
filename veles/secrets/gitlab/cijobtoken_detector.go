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
	_ veles.Detector = NewCIJobTokenDetector()
)

const (
	// maxTokenLength is the maximum length of a GitLab CI/CD Job Token
	// JWT tokens can be quite long (typically 500-800 characters)
	maxTokenLength = 1000
	// maxHostnameLength is the maximum length of a hostname
	maxHostnameLength = 255
	// maxDistance is the maximum distance between hostname and token to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// tokenRe matches GitLab CI/CD Job Tokens starting with glcbt- followed by JWT structure
// JWT consists of three base64url-encoded parts separated by dots
var tokenRe = regexp.MustCompile(`glcbt-[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// hostnameRe matches GitLab hostnames in URLs (gitlab.com or self-hosted instances)
// Matches the entire URL pattern including the protocol
// Examples: https://gitlab.example.com, http://gitlab.com
var hostnameRe = regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)`)

// FindAllHostname returns a function which finds all GitLab hostnames in URLs.
// It extracts the hostname from the capture group in the regex match.
func FindAllHostname() func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		matches := hostnameRe.FindAllSubmatchIndex(data, -1)
		var results []*pair.Match
		for _, m := range matches {
			// m[0], m[1] = full match positions
			// m[2], m[3] = first capture group positions (the hostname)
			if len(m) >= 4 {
				results = append(results, &pair.Match{
					Start: m[0],            // Use the full match start position
					Value: data[m[2]:m[3]], // Extract the captured hostname
				})
			}
		}
		return results
	}
}

// NewCIJobTokenDetector returns a new Detector that matches GitLab CI/CD Job Tokens.
// It uses pair detection to find hostnames near tokens, enabling validation
// against self-hosted GitLab instances.
func NewCIJobTokenDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxTokenLength, maxHostnameLength),
		MaxDistance:   maxDistance,
		FindA:         FindAllHostname(),
		FindB:         pair.FindAllMatches(tokenRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return CIJobToken{
				Token:    string(p.B.Value),
				Hostname: string(p.A.Value),
			}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			// Return token even if hostname is not found (defaults to gitlab.com)
			if p.B != nil {
				return CIJobToken{Token: string(p.B.Value)}, true
			}
			return nil, false
		},
	}
}
