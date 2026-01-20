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

package anthropicapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of an Anthropic API key.
const maxTokenLength = 200

// keyRe is a regular expression that matches an Anthropic API key.
// Anthropic API keys start with "sk-ant-" followed by an identifier
// (valid identifiers such as: api03, admin01, etc.)
// and base64-like characters with hyphens and underscores.
var keyRe = regexp.MustCompile(`sk-ant-[a-zA-Z0-9]+-[A-Za-z0-9_-]+`)

// NewDetector returns a new simpletoken.Detector that matches Anthropic API keys
// and returns the appropriate key type (WorkspaceAPIKey or ModelAPIKey) based on the key content.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			key := string(b)
			if IsWorkspaceKey(key) {
				return WorkspaceAPIKey{Key: key}, true
			}
			return ModelAPIKey{Key: key}, true
		},
	}
}
