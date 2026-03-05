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

package gitlab

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

var (
	// Ensure constructor satisfies the interface at compile time.
	_ veles.Detector = NewDeployTokenDetector()
)

const (
	// Maximum length for each component
	maxTokenLength    = 50
	maxUsernameLength = 100
	maxRepoURLLength  = 500

	// Maximum distance between token, username, and repository URL in bytes
	maxDistance = 1000
)

// Token pattern: gldt- followed by 20-30 alphanumeric characters and underscores
var tokenRe = regexp.MustCompile(`gldt-[a-zA-Z0-9_]{20,30}`)

// Username pattern: gitlab+deploy-token-{id} or common username field patterns
// Examples: gitlab+deploy-token-12345, username: myuser, user: deploy_user
var usernameRe = regexp.MustCompile(`(?:gitlab\+deploy-token-\d+|(?i:username|user|login)\s*[:=]\s*[a-zA-Z0-9_+-]+)`)

// Repository URL pattern: Matches both HTTPS and SSH (scp-style) GitLab URLs
// Examples: https://gitlab.com/org/project.git, git@gitlab.com:org/project.git
var repoURLRe = regexp.MustCompile(`(?:(?:https?|ssh)://(?:git@)?[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]/[a-zA-Z0-9_./+-]+\.git|git@[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]:[a-zA-Z0-9_./+-]+\.git)`)

// NewDeployTokenDetector returns a new Detector that matches GitLab Deploy Tokens.
// It uses ntuple detection to find token, username, and repository URL.
// When all three are found together, it returns a complete DeployToken.
// When only the token is found, it returns DeployToken with only the token field.
func NewDeployTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxTokenLength, maxUsernameLength, maxRepoURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(tokenRe),
			ntuple.FindAllMatches(usernameRe),
			ntuple.FindAllMatches(repoURLRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return DeployToken{
				Token:    string(ms[0].Value),
				Username: string(ms[1].Value),
				RepoURL:  string(ms[2].Value),
			}, true
		},
		FromPartial: func(m ntuple.Match) (veles.Secret, bool) {
			// Only return partial match if it's the token (FinderIndex 0)
			if m.FinderIndex == 0 {
				return DeployToken{Token: string(m.Value)}, true
			}
			return nil, false
		},
	}
}
