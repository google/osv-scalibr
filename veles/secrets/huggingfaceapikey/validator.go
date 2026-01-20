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

package huggingfaceapikey

import (
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	httpClientTimeout   = 10 * time.Second
	huggingFaceEndpoint = "https://huggingface.co/api/whoami-v2"
)

// NewValidator creates a validator for HuggingFace API keys.
//
// It performs a GET request to the Huggingface whoami endpoint
// using the API key in the Authorization header. If the request returns
// HTTP 200, the key is considered valid. If 401 Unauthorized, the key
// is invalid. If 429 TooManyRequests, we assume rate limiting and treat
// as valid to avoid false negatives. Other errors return ValidationFailed.
func NewValidator() *simplevalidate.Validator[HuggingfaceAPIKey] {
	return &simplevalidate.Validator[HuggingfaceAPIKey]{
		Endpoint:   huggingFaceEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k HuggingfaceAPIKey) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k.Key,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusTooManyRequests},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC:                &http.Client{Timeout: httpClientTimeout},
	}
}
