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
	_ veles.Detector = NewFeedTokenDetector()
)

const (
	feedTokenMaxLen = 50  // glft- (5) + ~20 chars + padding
	hostnameMaxLen  = 300 // Maximum reasonable hostname length
	maxDistance     = 500 // Maximum distance between hostname and token
)

// feedTokenRe matches GitLab Feed Tokens in the format:
// glft-[a-zA-Z0-9_-]{20}
var feedTokenRe = regexp.MustCompile(`glft-[a-zA-Z0-9_-]{20}`)

// hostnameRe matches hostnames in URLs
// Simplified pattern that matches domain names with alphanumeric characters and hyphens
var hostnameRe = regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)`)

// NewFeedTokenDetector returns a new Detector that matches GitLab Feed Tokens.
// It uses pair detection to find both the token and the associated GitLab hostname.
func NewFeedTokenDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(feedTokenMaxLen, hostnameMaxLen),
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(feedTokenRe),
		FindB:         findHostnames,
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			token := string(p.A.Value)
			hostname := string(p.B.Value)
			return FeedToken{
				Token:    token,
				Hostname: hostname,
			}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A != nil {
				// Token found without hostname, leave hostname empty
				// The validator will default to gitlab.com if needed
				return FeedToken{
					Token: string(p.A.Value),
				}, true
			}
			// Hostname without token is not useful
			return nil, false
		},
	}
}

// findHostnames extracts hostnames from URLs in the data
func findHostnames(data []byte) []*pair.Match {
	matches := hostnameRe.FindAllSubmatchIndex(data, -1)
	var results []*pair.Match
	for _, m := range matches {
		if len(m) >= 4 {
			// m[2] and m[3] are the start and end of the first capture group (hostname only)
			results = append(results, &pair.Match{
				Start: m[0],
				Value: data[m[2]:m[3]],
			})
		}
	}
	return results
}
