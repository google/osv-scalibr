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

// Package gitlabdeploytoken contains a Veles Secret type and a Detector for
// GitLab Deploy Tokens (prefix `gldt-`).
package gitlabdeploytoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

var (
	// Ensure constructor satisfies the interface at compile time.
	_ veles.Detector = NewDetector()
)

const (
	// maxTokenLength is the maximum length of a GitLab Deploy Token
	maxTokenLength = 100
	// maxUsernameLength is the maximum length of a username
	maxUsernameLength = 100
	// maxRepoURLLength is the maximum length of a repository URL
	maxRepoURLLength = 500
	// maxDistance is the maximum distance between elements to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// tokenRe matches GitLab Deploy Tokens starting with gldt- followed by alphanumeric and underscores
// Example: gldt-W6xaS96Cxzb87K5XsdAh, gldt-k3tx_ycYvssk_8FLUHju
var tokenRe = regexp.MustCompile(`gldt-[A-Za-z0-9_]{15,}`)

// usernameRe matches GitLab Deploy Token usernames in two formats:
//  1. Official: gitlab+deploy-token-{numbers} (e.g., gitlab+deploy-token-12535871)
//  2. Generic: key-value patterns like username: value, username=value, or username="value"
//     Captures only the value after username/user/login/account keywords
//
// Examples: username: myuser, username="deploy_token", login=testuser
var usernameRe = regexp.MustCompile(`gitlab\+deploy-token-\d+|(?i:username|user|login|account)["']?\s*[=:]\s*["']?([^"'\s]+)`)

// repoURLRe matches GitLab repository URLs in HTTPS, HTTP, and SSH formats
// Examples: https://gitlab.com/org/project.git, git@gitlab.com:org/project.git
var repoURLRe = regexp.MustCompile(`(?:(?:https?|ssh)://(?:git@)?[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]/[a-zA-Z0-9_./+-]+\.git|git@[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]:[a-zA-Z0-9_./+-]+\.git)`)

// NewDetector returns a new Detector that matches GitLab Deploy Tokens.
// It uses ntuple detection to find token, username, and repository URL.
// When all three are found together, it returns a complete GitlabDeployToken.
// When only the token is found, it returns GitlabDeployToken with only the token field.
func NewDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxTokenLength, maxUsernameLength, maxRepoURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(tokenRe),
			ntuple.FindAllMatchesGroup(usernameRe),
			ntuple.FindAllMatches(repoURLRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return GitlabDeployToken{
				Token:    string(ms[0].Value),
				Username: string(ms[1].Value),
				RepoURL:  string(ms[2].Value),
			}, true
		},
		FromPartial: func(m ntuple.Match) (veles.Secret, bool) {
			// Only return partial match if it's the token (FinderIndex 0)
			if m.FinderIndex == 0 {
				return GitlabDeployToken{Token: string(m.Value)}, true
			}
			return nil, false
		},
	}
}
