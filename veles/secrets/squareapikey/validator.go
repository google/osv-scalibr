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

package squareapikey

import (
	"net/http"
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	validationTimeout = 10 * time.Second
)

type spat = SquarePersonalAccessToken

// NewPersonalAccessTokenValidator creates a new Validator for Square Personal Access Tokens.
// It calls GET https://connect.squareup.com/v2/locations with header "Authorization: Bearer <key>".
// - 200 OK  -> authenticated and valid.
// - 401     -> invalid API key (authentication failure).
// - other   -> validation failed (unexpected response).
func NewPersonalAccessTokenValidator() *sv.Validator[spat] {
	return &sv.Validator[spat]{
		Endpoint:   "https://connect.squareup.com/v2/locations",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s spat) map[string]string {
			return map[string]string{
				"Authorization":  "Bearer " + s.Key,
				"Square-Version": "2024-07-17",
				"Content-Type":   "application/json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
