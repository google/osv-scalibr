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

package deepseekapikey

import (
	"encoding/json"
	"net/http"
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// deepseekAPIEndpoint is the DeepSeek chat completions API endpoint.
	deepseekAPIEndpoint = "https://api.deepseek.com/chat/completions"
	// validationTimeout is the timeout for API validation requests.
	validationTimeout = 10 * time.Second
)

// NewAPIValidator creates a new DeepSeek API key Validator.
// It performs a POST request to the DeepSeek chat completions endpoint
// using the API key in the Authorization header. If the request returns
// HTTP 200, 402, 403, or 429, the key is considered valid (these indicate
// the key exists but may have billing, permission, or rate-limiting issues).
// If 401 Unauthorized, the key is invalid.
func NewAPIValidator() *sv.Validator[APIKey] {
	return &sv.Validator[APIKey]{
		Endpoint:   deepseekAPIEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(s APIKey) map[string]string {
			return map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer " + s.Key,
			}
		},
		Body: func(_ APIKey) (string, error) {
			payload, err := json.Marshal(map[string]any{
				"model": "deepseek-chat",
				"messages": []map[string]string{
					{"role": "user", "content": "Hello!"},
				},
				"stream": false,
			})
			return string(payload), err
		},
		ValidResponseCodes: []int{
			http.StatusOK,
			http.StatusPaymentRequired,
			http.StatusForbidden,
			http.StatusTooManyRequests,
		},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
