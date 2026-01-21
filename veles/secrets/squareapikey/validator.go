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
	"io"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
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
//   - HTTP 400 Bad Request with JSON body containing:
//     {"errors": [{"code": "NOT_FOUND", "detail": "access token not found"}]}
//   - This indicates the credentials are VALID (they authenticated successfully, but the
//     random access token doesn't exist, which is expected)
//
// Invalid Credentials Response:
//   - HTTP 401 Unauthorized with JSON body containing:
//     {"message": "Not Authorized", "type": "service.not_authorized"}
//   - This indicates the credentials are INVALID (authentication failed)
//
// Validation Requirements:
//   - Both ID and Secret must be present (non-empty)
//   - If either is missing, the Body function will return an error which results in ValidationFailed
//   - This is acceptable since partial pairs (secret without ID) shouldn't be validated
//
// API Endpoint: POST https://connect.squareup.com/oauth2/revoke
// Request Headers:
//   - Content-Type: application/json
//   - Authorization: Client <client_secret>
//
// Request Body:
//   - access_token: "RANDOM_STRING" (intentionally fake)
//   - client_id: <oauth_application_id>
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
			// This is acceptable since partial pairs shouldn't be validated
			if s.ID == "" || s.Key == "" {
				return "", io.EOF // Return a simple error
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
		// Custom validation logic to handle Square's specific response format
		// This runs when the status code doesn't match ValidResponseCodes or InvalidResponseCodes
		StatusFromResponseBody: func(body io.Reader) (veles.ValidationStatus, error) {
			// Read the response body
			bodyBytes, err := io.ReadAll(body)
			if err != nil {
				return veles.ValidationFailed, err
			}

			// Parse the JSON response
			var response map[string]any
			if err := json.Unmarshal(bodyBytes, &response); err != nil {
				// If we can't parse JSON, it's a validation failure
				return veles.ValidationFailed, err
			}

			// Check for "Not Authorized" message (invalid credentials)
			if msg, ok := response["message"].(string); ok && msg == "Not Authorized" {
				return veles.ValidationInvalid, nil
			}

			// Check for "access token not found" error (valid credentials)
			// This is the expected response when credentials are valid but the access token is fake
			if errors, ok := response["errors"].([]any); ok && len(errors) > 0 {
				if errorMap, ok := errors[0].(map[string]any); ok {
					if code, ok := errorMap["code"].(string); ok && code == "NOT_FOUND" {
						if detail, ok := errorMap["detail"].(string); ok && detail == "access token not found" {
							return veles.ValidationValid, nil
						}
					}
				}
			}

			// Any other response is considered a validation failure
			return veles.ValidationFailed, nil
		},
		// 401 Unauthorized typically means invalid credentials
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
