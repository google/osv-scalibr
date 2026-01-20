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

package openai

import (
	"net/http"
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// OpenAI API base URL.
	openaiAPIBaseURL = "https://api.openai.com"
	// Timeout for API validation requests.
	validationTimeout = 10 * time.Second
	// ModelsEndpoint is the OpenAI models API endpoint.
	ModelsEndpoint = "/v1/models"
)

// NewProjectValidator creates a new ProjectValidator that validates API keys by
// making a test request to the OpenAI API /v1/models endpoint.
func NewProjectValidator() *sv.Validator[APIKey] {
	v := &sv.Validator[APIKey]{
		Endpoint:   openaiAPIBaseURL + ModelsEndpoint,
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

	return v
}
