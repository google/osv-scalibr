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

package supabase

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewPATValidator creates a new Supabase Personal Access Token Validator.
// It performs a GET request to the Supabase Management API /v1/projects endpoint
// using the PAT in the Authorization header with Bearer scheme.
// If the request returns HTTP 200, the token is considered valid.
// If 401 Unauthorized, the token is invalid. Other errors return ValidationFailed.
func NewPATValidator() *sv.Validator[PAT] {
	return &sv.Validator[PAT]{
		Endpoint:   "https://api.supabase.com/v1/projects",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s PAT) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + s.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}

// NewProjectSecretKeyValidator creates a new Supabase Project Secret Key Validator.
// This validator only works when the ProjectSecretKey has both Key and ProjectRef fields populated.
// It validates by making a request to the project-specific Supabase REST endpoint.
// If only the Key is present (ProjectRef is empty), validation returns ValidationFailed with an error.
func NewProjectSecretKeyValidator() *sv.Validator[ProjectSecretKey] {
	return &sv.Validator[ProjectSecretKey]{
		EndpointFunc: func(secret ProjectSecretKey) (string, error) {
			if secret.ProjectRef == "" {
				return "", errors.New("project reference not present; cannot validate secret key alone")
			}
			return fmt.Sprintf("https://%s.supabase.co/rest/v1/", secret.ProjectRef), nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(secret ProjectSecretKey) map[string]string {
			return map[string]string{
				"apikey":        secret.Key,
				"Authorization": "Bearer " + secret.Key,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}

// NewServiceRoleJWTValidator creates a new Supabase Service Role JWT Validator.
// This validator extracts the project reference from the JWT's aud claim (if present)
// It validates by making a request to the project-specific Supabase REST endpoint.
func NewServiceRoleJWTValidator() *sv.Validator[ServiceRoleJWT] {
	return &sv.Validator[ServiceRoleJWT]{
		EndpointFunc: func(secret ServiceRoleJWT) (string, error) {
			// Try to extract project reference from JWT
			projectRef, err := extractProjectRefFromJWT(secret.Token)
			if err != nil {
				return "", fmt.Errorf("cannot extract project reference from JWT: %w", err)
			}

			if projectRef == "" {
				return "", errors.New("project reference not found in JWT; cannot validate without project context")
			}

			return fmt.Sprintf("https://%s.supabase.co/rest/v1/", projectRef), nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(secret ServiceRoleJWT) map[string]string {
			return map[string]string{
				"apikey":        secret.Token,
				"Authorization": "Bearer " + secret.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}

// extractProjectRefFromJWT attempts to extract the project reference from a JWT token.
// Supabase JWTs contain the project reference in the "ref" claim.
func extractProjectRefFromJWT(token string) (string, error) {
	// Split JWT into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON payload to extract project reference
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	// Extract project reference from the "ref" claim
	// Example: {"iss":"supabase","ref":"project-id","role":"service_role",...}
	if ref, ok := claims["ref"].(string); ok && len(ref) == 20 {
		return ref, nil
	}

	return "", errors.New("ref claim not found or invalid in JWT")
}
