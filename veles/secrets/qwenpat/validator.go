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
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// validationTimeout is the timeout for a single DashScope endpoint query.
const validationTimeout = 10 * time.Second

// dashScopeModels are the DashScope model list endpoints of all four regional
// domains. API keys are bound to the region they were created in, so a key is
// only reported as invalid when none of the endpoints accepts it.
var dashScopeModels = []string{
	"https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models",
	"https://dashscope-us.aliyuncs.com/compatible-mode/v1/models",
	"https://cn-hongkong.dashscope.aliyuncs.com/compatible-mode/v1/models",
	"https://dashscope.aliyuncs.com/compatible-mode/v1/models",
}

// NewValidator creates a new Validator checks whether the given QwenPAT is valid via the DashScope API.
//
// It performs a GET request to each of the four DashScope regional endpoints
// until one of them returns a definitive answer.
// If any request returns HTTP 200 or 400, the key is considered valid.
// If every request returns 401 Unauthorized or 403 Forbidden, the key is invalid.
// Other errors return ValidationFailed.
// See following links:
// 1. https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope
// 2. https://www.alibabacloud.com/help/en/model-studio/error-code
// 3. https://www.alibabacloud.com/help/en/model-studio/base-url#dashscope-domain
func NewValidator() *sv.Validator[QwenPAT] {
	return &sv.Validator[QwenPAT]{
		Endpoints:  dashScopeModels,
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
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
