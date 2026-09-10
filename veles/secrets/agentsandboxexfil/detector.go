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

package agentsandboxexfil

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// exfilRe matches patterns typical of DNS tunneling or IMDS probing in agent scripts.
	// 1. Matches DNS tunneling subdomains with base64-like strings or templates (f-strings).
	// 2. Matches hardcoded references to the Metadata server (IMDS).
	exfilRe = regexp.MustCompile(`(?i)(v1-[0-9]+-[a-zA-Z0-9+/]{20,}|v1-(?:\{.*?\}-?)+|v1-%s|169\.254\.169\.254|metadata\.google\.internal)`)
)

// NewDetector returns a detector for Agent Sandbox exfiltration attempts.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: 1024,
		Re:     exfilRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return AgentSandboxExfil{Pattern: string(b)}, true
		},
	}
}
