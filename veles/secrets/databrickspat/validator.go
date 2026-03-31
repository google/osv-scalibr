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

package databrickspat

import (
	"errors"
	"fmt"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// TokenListEndpoint is the read-only Databricks REST API endpoint used for validation.
// GET /api/2.0/token/list lists PATs without side effects.
// Reference: https://docs.databricks.com/api/gcp/workspace/tokens/list
const TokenListEndpoint = "/api/2.0/token/list"

// NewValidator creates a Validator that validates Databricks PAT credentials
// by sending a GET request to the workspace's /api/2.0/token/list endpoint.
//
// Validation logic:
//   - HTTP 200: Token is valid and has sufficient permissions
//   - HTTP 403: Token is valid but lacks the required scope (still confirms validity)
//   - HTTP 401: Token is invalid
//
// This endpoint is read-only and has no side effects.
func NewValidator() *sv.Validator[PATCredentials] {
	return &sv.Validator[PATCredentials]{
		EndpointFunc: func(creds PATCredentials) (string, error) {
			if creds.Token == "" || creds.URL == "" {
				return "", errors.New("token or workspace URL is empty")
			}
			return fmt.Sprintf("https://%s%s", creds.URL, TokenListEndpoint), nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(creds PATCredentials) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + creds.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusForbidden},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
