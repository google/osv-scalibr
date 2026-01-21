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

package circleci

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/osv-scalibr/veles"
	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewPersonalAccessTokenValidator creates a new CircleCI Personal Access Token Validator.
// It performs a GET request to the CircleCI /api/v2/me endpoint
// using the token in the Circle-Token header.
//
// Validation logic:
// - HTTP 200 OK: Token is valid and authenticated
// - HTTP 401 Unauthorized: Token is invalid
// - Other status codes: Validation failed (unexpected response)
func NewPersonalAccessTokenValidator() *sv.Validator[PersonalAccessToken] {
	return &sv.Validator[PersonalAccessToken]{
		Endpoint:   "https://circleci.com/api/v2/me",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s PersonalAccessToken) map[string]string {
			return map[string]string{
				"Circle-Token": s.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}

// projectTokenErrorResponse models CircleCI's v1.1 API error JSON.
type projectTokenErrorResponse struct {
	Message string `json:"message"`
}

func statusFromProjectTokenResponseBody(body io.Reader) (veles.ValidationStatus, error) {
	var resp projectTokenErrorResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		// Decoding failed -> ambiguous response, treat as failed to validate.
		return veles.ValidationFailed, fmt.Errorf("unable to parse response: %w", err)
	}

	// CircleCI returns 404 with "Not Found" when the token is valid but the project doesn't exist.
	// This confirms the token was successfully authenticated.
	if resp.Message == "Not Found" {
		return veles.ValidationValid, nil
	}

	// Other error messages (like "Invalid token provided.") indicate the token is invalid.
	return veles.ValidationInvalid, nil
}

// NewProjectTokenValidator creates a new CircleCI Project Token Validator.
//
// Validation approach:
// CircleCI Project tokens are validated by attempting to access a non-existent project.
// We use HTTP Basic Auth with the token as username and empty password.
//
// Validation logic:
// - HTTP 200 OK: Token is valid and has access to the project (rare with dummy project)
// - HTTP 404 with {"message":"Not Found"}: Token is valid but project doesn't exist (expected)
// - HTTP 401 Unauthorized: Token is invalid
// - Other status codes: Validation failed (unexpected response)
//
// The dummy project path includes a random string to avoid any accidental matches with real projects.
func NewProjectTokenValidator() *sv.Validator[ProjectToken] {
	return &sv.Validator[ProjectToken]{
		// Use a dummy project path with random string to ensure it doesn't exist
		Endpoint:   "https://circleci.com/api/v1.1/project/scalibr-validation-nonexistent-a8f3c2d9",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s ProjectToken) map[string]string {
			// Encode token as Basic Auth: base64(token:)
			// The colon after the token indicates an empty password
			auth := base64.StdEncoding.EncodeToString([]byte(s.Token + ":"))
			return map[string]string{
				"Accept":        "application/json",
				"Authorization": "Basic " + auth,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		// StatusFromResponseBody handles 404 responses to check for "Not Found" message
		StatusFromResponseBody: statusFromProjectTokenResponseBody,
	}
}
