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

package anthropicapikey

import (
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// AnthropicWorkspacesEndpoint is the Anthropic API workspaces endpoint
const AnthropicWorkspacesEndpoint = "/v1/organizations/workspaces"

// NewWorkspaceValidator creates a new Validator for the Anthropic workspace API
// keys.
func NewWorkspaceValidator() *simplevalidate.Validator[WorkspaceAPIKey] {
	return &simplevalidate.Validator[WorkspaceAPIKey]{
		Endpoint:   anthropicAPIBaseURL + AnthropicWorkspacesEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k WorkspaceAPIKey) map[string]string {
			return map[string]string{
				"X-Api-Key":         k.Key,
				"Anthropic-Version": anthropicAPIVersion,
			}
		},
		// StatusTooManyRequests indicates that the key successfully authenticates
		// against the Anthropic API and that this account is rate limited.
		ValidResponseCodes:   []int{http.StatusOK, http.StatusTooManyRequests},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
