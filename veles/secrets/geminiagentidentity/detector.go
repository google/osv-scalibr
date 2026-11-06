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

package geminiagentidentity

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// agentIdentityRe matches Gemini Agent Identity SPIFFE strings.
	// Example: principal://agents.global.google.com/projects/my-project/locations/us-central1/agents/my-agent
	agentIdentityRe = regexp.MustCompile(`(?i)principal://agents\.global\.google\.com/projects/[a-zA-Z0-9-]+/locations/[a-z0-9-]+/agents/[a-zA-Z0-9-]+`)
)

// NewDetector returns a detector for Gemini Agent Identities.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: 1024,
		Re:     agentIdentityRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return GeminiAgentIdentity{Identity: string(b)}, true
		},
	}
}
