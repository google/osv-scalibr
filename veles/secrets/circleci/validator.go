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
	"net/http"

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

// NewProjectTokenValidator creates a new CircleCI Project Token Validator.
//
// Validation approach:
// CircleCI Project tokens are validated by attempting to access a non-existent project.
// We use the Circle-Token header with the token value.
//
// Validation logic:
// - HTTP 200 OK: Token is valid and has access to the project (rare with dummy project)
// - HTTP 404 Not Found: Token is valid but project doesn't exist (expected)
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
			return map[string]string{
				"Circle-Token": s.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusNotFound},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
