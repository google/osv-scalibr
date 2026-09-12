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

package cohereapikey

import (
	"net/http"
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// Cohere API base URL.
	cohereAPIBaseURL = "https://api.cohere.com"
	// Timeout for API validation requests.
	validationTimeout = 10 * time.Second
	// ModelsEndpoint is the Cohere API models endpoint.
	ModelsEndpoint = "/v2/models"
)

// NewValidator creates a new Validator that validates API keys by making a
// test request to the Cohere API /v2/models endpoint.
// Cohere API keys use Bearer token authentication.
func NewValidator() *sv.Validator[APIKey] {
	return &sv.Validator[APIKey]{
		Endpoint:   cohereAPIBaseURL + ModelsEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k APIKey) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k.Key,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusTooManyRequests},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
