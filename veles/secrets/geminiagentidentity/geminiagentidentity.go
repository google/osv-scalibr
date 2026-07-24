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

import "github.com/google/osv-scalibr/veles"

// GeminiAgentIdentity represents a detected Gemini Agent Identity (SPIFFE ID).
type GeminiAgentIdentity struct {
	veles.Secret
	Identity string
}

// Type returns the secret type.
func (s GeminiAgentIdentity) Type() string { return "gemini_agent_identity" }

// Description returns a description of the secret.
func (s GeminiAgentIdentity) Description() string {
	return "Gemini Agent Identity (SPIFFE ID) detected."
}
