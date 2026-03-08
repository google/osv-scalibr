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

package gitlab

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

var (
	_ veles.Validator[FeatureFlagsClientToken] = &FeatureFlagsClientTokenValidator{}
)

// FeatureFlagsClientTokenValidator validates GitLab Feature Flags Client Tokens
// by attempting to access the Unleash API endpoint.
//
// Validation approach:
//   - Uses the provided endpoint URL (e.g., https://gitlab.com/api/v4/feature_flags/unleash/79858780)
//   - Sends HTTP GET with Authorization header containing the token
//   - 200 OK = valid token with access to feature flags
//   - 401 Unauthorized = invalid token or credentials
type FeatureFlagsClientTokenValidator struct {
	validator *simplevalidate.Validator[FeatureFlagsClientToken]
}

// NewFeatureFlagsClientTokenValidator creates a new GitLab Feature Flags Client Token validator
func NewFeatureFlagsClientTokenValidator() *FeatureFlagsClientTokenValidator {
	return &FeatureFlagsClientTokenValidator{
		validator: &simplevalidate.Validator[FeatureFlagsClientToken]{
			// EndpointFunc returns the validation URL from the endpoint field.
			EndpointFunc: func(secret FeatureFlagsClientToken) (string, error) {
				// Validation requires an endpoint URL
				if secret.Endpoint == "" {
					return "", errors.New("endpoint is required for validation")
				}
				return secret.Endpoint, nil
			},
			HTTPMethod: http.MethodGet,
			// HTTPHeaders sets up Authorization header with the token.
			// GitLab Feature Flags API expects: "Authorization: <token>"
			HTTPHeaders: func(secret FeatureFlagsClientToken) map[string]string {
				return map[string]string{
					"Authorization": secret.Token,
				}
			},
			// ValidResponseCodes: 200 indicates the token is valid and has access
			ValidResponseCodes: []int{http.StatusOK},
			// InvalidResponseCodes: 401 indicates invalid credentials
			InvalidResponseCodes: []int{http.StatusUnauthorized},
			HTTPC: &http.Client{
				Timeout: 10 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
		},
	}
}

// Validate checks if the GitLab Feature Flags Client Token is valid by attempting
// to access the Unleash API endpoint with the provided token.
//
// Returns:
//   - veles.ValidationStatusValid: Token is valid (200 OK)
//   - veles.ValidationStatusInvalid: Token is invalid (401 Unauthorized)
//   - error: Network errors or other validation failures
func (v *FeatureFlagsClientTokenValidator) Validate(ctx context.Context, secret FeatureFlagsClientToken) (veles.ValidationStatus, error) {
	return v.validator.Validate(ctx, secret)
}
