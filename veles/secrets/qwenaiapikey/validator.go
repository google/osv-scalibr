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
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// Qwen AI compatible API base URL (DashScope international).
	qwenAPIBaseURL = "https://dashscope-intl.aliyuncs.com"
	// Timeout for API validation requests.
	validationTimeout = 10 * time.Second
	// ModelsEndpoint is the Qwen AI models API endpoint.
	ModelsEndpoint = "/compatible-mode/v1/models"
)

// NewValidator creates a new Validator that validates Qwen AI API keys by
// making a test request to the DashScope models endpoint.
// A valid key returns 200 OK with the list of supported models.
// An invalid or revoked key returns 401 Unauthorized.
func NewValidator() *sv.Validator[APIKey] {
	return &sv.Validator[APIKey]{
		Endpoint:   qwenAPIBaseURL + ModelsEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k APIKey) map[string]string {
			return map[string]string{"Authorization": "Bearer " + k.Key}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusTooManyRequests},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
