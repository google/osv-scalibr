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

package hashicorpvault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const httpClientTimeout = 10 * time.Second

// NewTokenValidator creates a new TokenValidator with the given ValidatorOptions.
//
// Checks whether the given Token is valid by using the Vault token lookup-self API.
// It performs a GET request to /v1/auth/token/lookup-self with the token in the X-Vault-Token header.
// Returns ValidationValid for 200 OK, ValidationInvalid for 401/403, ValidationFailed for other errors.
func NewTokenValidator() *simplevalidate.Validator[Token] {
	v := &simplevalidate.Validator[Token]{
		Endpoint:   "https://vault.company.com/v1/auth/token/lookup-self",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k Token) map[string]string {
			return map[string]string{
				"X-Vault-Token": k.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
		HTTPC:                &http.Client{Timeout: httpClientTimeout},
	}
	return v
}

// NewAppRoleValidator creates a new AppRoleValidator with the given ValidatorOptions.
//
// Validate checks whether the given AppRoleCredentials are valid by using the Vault AppRole login API.
// It performs a POST request to /v1/auth/approle/login with role-id and secret-id.
// Note: Since the detector cannot distinguish between role-id and secret-id, this validation
// is limited. In practice, both values would need to be provided together.
// Returns ValidationValid for 200 OK, ValidationInvalid for 401/400, ValidationFailed for other errors.
func NewAppRoleValidator() *simplevalidate.Validator[AppRoleCredentials] {
	v := &simplevalidate.Validator[AppRoleCredentials]{
		Endpoint:   "https://vault.company.com/v1/auth/approle/login",
		HTTPMethod: http.MethodPost,
		Body: func(k AppRoleCredentials) (string, error) {
			if k.RoleID == "" || k.SecretID == "" {
				return "", errors.New("both role_id and secret_id are required for AppRole validation")
			}
			body := AppRoleLoginRequest{
				RoleID:   k.RoleID,
				SecretID: k.SecretID,
			}
			jsonBody, err := json.Marshal(body)
			if err != nil {
				return "", fmt.Errorf("failed to marshal AppRoleLoginRequest: %w", err)
			}
			return string(jsonBody), nil
		},
		HTTPHeaders: func(k AppRoleCredentials) map[string]string {
			return map[string]string{
				"Content-Type": "application/json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusBadRequest},
		HTTPC:                &http.Client{Timeout: httpClientTimeout},
	}
	return v
}

// AppRoleLoginRequest represents the request body for AppRole login.
type AppRoleLoginRequest struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}
