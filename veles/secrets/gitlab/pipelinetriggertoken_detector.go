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
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

var (
	// Ensure constructor satisfies the interface at compile time.
	_ veles.Detector = NewPipelineTriggerTokenDetector()
)

const (
	// maxTriggerTokenLength is the maximum length of a GitLab Pipeline Trigger Token
	maxTriggerTokenLength = 100
	// maxInstanceURLLength is the maximum length of a GitLab instance URL component
	maxInstanceURLLength = 300
	// maxTriggerDistance is the maximum distance between elements to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxTriggerDistance = 10 * 1 << 10 // 10 KiB
)

// triggerTokenRe matches GitLab Pipeline Trigger Tokens starting with glptt- followed by alphanumeric, hyphens, and underscores
// Uses negative lookahead to ensure we don't match beyond valid token characters
// Example: glptt-zHDqwggzUPPp5PgxBUN7, glptt-c2cpyCxbRRe5FjC-RsN4, glptt-xJwYxEM6ygnH_ooTrYMe
var triggerTokenRe = regexp.MustCompile(`glptt-[A-Za-z0-9_-]{15,}(?:[^A-Za-z0-9_-]|$)`)

// instanceURLRe matches GitLab instance URLs and extracts hostname and project ID
// Matches patterns like:
//  1. Full URLs: https://gitlab.com/api/v4/projects/79858780/trigger/pipeline
//  2. Full URLs: https://gitlab.example.com/api/v4/projects/12345/trigger/pipeline
//
// Capture groups:
//  1. Hostname (e.g., "gitlab.com", "gitlab.example.com")
//  2. Project ID (numeric)
var instanceURLRe = regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9])(?::\d+)?/(?:api/v4/)?projects/(\d+)`)

// findInstanceURL finds all GitLab instance URLs in the data and extracts hostname and project ID
func findInstanceURL(data []byte) []ntuple.Match {
	matches := instanceURLRe.FindAllSubmatchIndex(data, -1)
	var results []ntuple.Match
	for _, m := range matches {
		// m[0], m[1] = full match positions
		// m[2], m[3] = hostname capture group
		// m[4], m[5] = project ID capture group
		if len(m) >= 6 && m[2] != -1 && m[4] != -1 {
			hostname := data[m[2]:m[3]]
			projectID := data[m[4]:m[5]]
			// Store both hostname and project ID separated by a pipe character
			value := append(append(hostname, '|'), projectID...)
			results = append(results, ntuple.Match{
				Start: m[0],
				Value: value,
			})
		}
	}
	return results
}

// findTriggerToken finds all trigger tokens in the data, excluding the boundary character
func findTriggerToken(data []byte) []ntuple.Match {
	matches := triggerTokenRe.FindAllIndex(data, -1)
	var results []ntuple.Match
	for _, m := range matches {
		// The regex includes a boundary character at the end, so we need to trim it
		tokenEnd := m[1]
		if tokenEnd > m[0] && tokenEnd <= len(data) {
			// Check if the last character is a boundary character (not part of token)
			lastChar := data[tokenEnd-1]
			if !((lastChar >= 'A' && lastChar <= 'Z') || (lastChar >= 'a' && lastChar <= 'z') ||
				(lastChar >= '0' && lastChar <= '9') || lastChar == '-' || lastChar == '_') {
				tokenEnd--
			}
		}

		if tokenEnd > m[0] {
			results = append(results, ntuple.Match{
				Start: m[0],
				Value: data[m[0]:tokenEnd],
			})
		}
	}
	return results
}

// NewPipelineTriggerTokenDetector returns a new Detector that matches GitLab Pipeline Trigger Tokens.
// It uses ntuple detection to find token and instance URL (hostname + project ID).
// When both are found together, it returns a complete PipelineTriggerToken with hostname and project ID.
// When only the token is found, it returns PipelineTriggerToken with only the token field.
func NewPipelineTriggerTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxTriggerTokenLength, maxInstanceURLLength),
		MaxDistance:   maxTriggerDistance,
		Finders: []ntuple.Finder{
			findTriggerToken,
			findInstanceURL,
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			// ms[1].Value contains "hostname|projectID"
			parts := strings.SplitN(string(ms[1].Value), "|", 2)
			if len(parts) != 2 {
				return nil, false
			}
			return PipelineTriggerToken{
				Token:     string(ms[0].Value),
				Hostname:  parts[0],
				ProjectID: parts[1],
			}, true
		},
		FromPartial: func(m ntuple.Match) (veles.Secret, bool) {
			// Only return partial match if it's the token (FinderIndex 0)
			if m.FinderIndex == 0 {
				return PipelineTriggerToken{Token: string(m.Value)}, true
			}
			return nil, false
		},
	}
}
