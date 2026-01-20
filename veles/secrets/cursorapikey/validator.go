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

package cursorapikey

import (
	"encoding/base64"
	"net/http"
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// Cursor API base URL.
	cursorAPIBaseURL = "https://api.cursor.com"
	// Timeout for API validation requests.
	validationTimeout = 10 * time.Second
	// MeEndpoint is the Cursor API me endpoint.
	MeEndpoint = "/v0/me"
)

// NewValidator creates a new Validator that validates API keys by making a
// test request to the Cursor API /v0/me endpoint.
// Cursor API keys use Basic Authentication with the key as username and
// blank password.
func NewValidator() *sv.Validator[APIKey] {
	v := &sv.Validator[APIKey]{
		Endpoint:   cursorAPIBaseURL + MeEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k APIKey) map[string]string {
			// Basic Auth: base64(key:)
			auth := base64.StdEncoding.EncodeToString([]byte(k.Key + ":"))
			return map[string]string{
				"Authorization": "Basic " + auth,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusTooManyRequests},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}

	return v
}
