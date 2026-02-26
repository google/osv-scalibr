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

// Package clojarsdeploytoken contains a Veles Secret type and a Detector for
// Clojars Deploy Tokens (prefix `CLOJARS_`).
package clojarsdeploytoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxTokenLength is the maximum size of a Clojars deploy token.
	// "CLOJARS_" (8) + 60 hex characters = 68
	maxTokenLength = 68
	// maxUsernameLength is the maximum size of the username field. Since clojars
	// allows signin with GitLab and GitLab allows a username of max 255 chars
	maxUsernameLength = 255

	// maxContextLength is the maximum size of the context
	maxContextLength = 50

	// maxDistance is the maximum distance between the username and the PAT. Since
	// maxUsernameLength is 255 to added 200 on top of usual 100 to make it 300
	maxDistance = 300
)

var (
	// patRe matches the strict format: "CLOJARS_" followed by exactly 60 hex characters.
	patRe = regexp.MustCompile(`CLOJARS_[a-f0-9]{60}`)

	// usernamePattern matches Clojars usernames in various formats.
	// It handles case-insensitivity for "username" and "clojars_username",
	// optional spaces, optional colons/equals signs, and optional quotes.
	usernamePattern = regexp.MustCompile(`(?i:(?:clojars_)?username)["']?\s*[=:]?\s*["']?([^"'\s]+)`)
)

// NewDetector returns a new Detector that matches
// Clojars Deploy Tokens.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxTokenLength, maxContextLength+maxUsernameLength), MaxDistance: maxDistance,
		FindA: pair.FindAllMatches(patRe),
		FindB: findUsernameMatches(),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return ClojarsDeployToken{Token: string(p.A.Value), Username: string(p.B.Value)}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A == nil {
				return nil, false
			}
			return ClojarsDeployToken{Token: string(p.A.Value)}, true
		},
	}
}

func findUsernameMatches() func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		res := []*pair.Match{}
		matches := usernamePattern.FindAllSubmatchIndex(data, -1)
		for _, m := range matches {
			res = append(res, &pair.Match{
				// m[0] is the start index of the entire match
				Start: m[0],
				// m[2]:m[3] targets the first capture group (the actual username value)
				Value: data[m[2]:m[3]],
			})
		}
		return res
	}
}
