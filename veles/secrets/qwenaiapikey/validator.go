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

package qwenaiapikey

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// dashScopeGenerationEndpoint is the API endpoint for DashScope model generation.
	dashScopeGenerationEndpoint = "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
)

// NewValidator creates a new Validator that validates the QwenAIAPIKey via
// the DashScope API.
//
// It performs a POST request to the generation endpoint.
// - If the API key is valid but the body is empty/invalid, we expect 400 Bad Request.
// - If the API key is invalid, we expect 401 Unauthorized or 403 Forbidden.
// - 200 OK is theoretically possible if we sent a valid payload, but 400 is enough to prove auth worked.
func NewValidator() *sv.Validator[QwenAIAPIKey] {
	return &sv.Validator[QwenAIAPIKey]{
		Endpoint:   dashScopeGenerationEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(s QwenAIAPIKey) map[string]string {
			return map[string]string{"Authorization": "Bearer " + s.Key}
		},
		// 200 OK: Request succeeded (unlikely with empty body but implies valid auth)
		// 400 Bad Request: Auth succeeded, but request parameters were invalid (implies valid auth)
		ValidResponseCodes: []int{http.StatusOK, http.StatusBadRequest},
		// 401 Unauthorized: Invalid API Key
		// 403 Forbidden: API Key valid format but permission denied/invalid
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
	}
}
