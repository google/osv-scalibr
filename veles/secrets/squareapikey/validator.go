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
	"encoding/json"
	"errors"
	"net/http"
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	validationTimeout = 10 * time.Second
)

type spat = SquarePersonalAccessToken
type soauth = SquareOAuthApplicationSecret

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

// NewOAuthApplicationSecretValidator creates a new Validator for Square OAuth Application Secrets.
//
// The validation works by attempting to revoke a fake/random access token using the provided
// credentials. Square's API behavior allows us to distinguish between valid and invalid credentials:
//
// Valid Credentials Response:
//   - HTTP 200 OK - token was successfully revoked (unlikely since we use a random access token)
//   - HTTP 404 Not Found - credentials authenticated successfully, but the random access token
//     doesn't exist (this is the expected response)
//
// Invalid Credentials Response:
//   - HTTP 401 Unauthorized - authentication failed
func NewOAuthApplicationSecretValidator() *sv.Validator[soauth] {
	return &sv.Validator[soauth]{
		Endpoint:   "https://connect.squareup.com/oauth2/revoke",
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(s soauth) map[string]string {
			return map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Client " + s.Key,
			}
		},
		Body: func(s soauth) (string, error) {
			// If either ID or Secret is missing, we can't validate
			// Return an error which will result in ValidationFailed
			if s.ID == "" || s.Key == "" {
				return "", errors.New("ID or Key isn't set")
			}

			// Use a random/fake access token - we're only testing if the credentials authenticate
			requestBody := map[string]string{
				"access_token": "RANDOM_STRING",
				"client_id":    s.ID,
			}
			jsonBody, err := json.Marshal(requestBody)
			if err != nil {
				return "", err
			}
			return string(jsonBody), nil
		},
		// 200 OK and 404 Not Found both mean credentials are valid
		// - 200 OK: token was successfully revoked (unlikely since we use a random access token)
		// - 404 Not Found: credentials authenticated successfully, but the random access token
		//   doesn't exist (this is the expected response)
		ValidResponseCodes: []int{http.StatusOK, http.StatusNotFound},
		// 401 Unauthorized means invalid credentials (authentication failed)
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
