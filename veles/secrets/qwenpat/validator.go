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

package qwenpat

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// dashScopeModels is the API endpoint for DashScope model list.
	dashScopeModels = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models"
)

// NewValidator creates a new Validator checks whether the given QwenPAT is valid via the DashScope API.
//
// It performs a GET request to the appropriate Qwen API endpoint
// If the request returns HTTP 200, the key is considered valid.
// If 401 Unauthorized, the key is invalid. Other errors return ValidationFailed.
// See following links:
// 1. https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope
// 2. https://www.alibabacloud.com/help/en/model-studio/error-code
func NewValidator() *sv.Validator[QwenPAT] {
	return &sv.Validator[QwenPAT]{
		Endpoint:   dashScopeModels,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s QwenPAT) map[string]string {
			return map[string]string{"Authorization": "Bearer " + s.Pat}
		},
		// 200 OK: Request succeeded (implies valid auth)
		// 400 Bad Request: Auth succeeded, but request parameters were invalid (implies valid auth)
		ValidResponseCodes: []int{http.StatusOK, http.StatusBadRequest},
		// 401 Unauthorized: Invalid API Key
		// 403 Forbidden: API Key valid format but permission denied/invalid
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
	}
}
