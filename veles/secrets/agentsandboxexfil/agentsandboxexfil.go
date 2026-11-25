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

import "github.com/google/osv-scalibr/veles"

// AgentSandboxExfil represents a detected AI agent sandbox exfiltration script or pattern.
type AgentSandboxExfil struct {
	veles.Secret
	Pattern string
}

// Type returns the secret type.
func (s AgentSandboxExfil) Type() string { return "agent_sandbox_exfil" }

// Description returns a description of the secret.
func (s AgentSandboxExfil) Description() string {
	return "Suspicious AI agent sandbox exfiltration script or DNS tunneling pattern detected."
}
