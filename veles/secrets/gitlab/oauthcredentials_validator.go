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
	"net/url"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	httpClientTimeout   = 10 * time.Second
	gitlabOAuthEndpoint = "https://gitlab.com/oauth/token"
	dummyAuthCode       = "INVALID_AUTHORIZATION_CODE_FOR_VALIDATION"
	dummyRedirectURI    = "https://example.com/callback"
)

var (
	_ veles.Validator[OAuthCredentials] = &OAuthCredentialsValidator{}
)

// OAuthCredentialsValidator validates GitLab OAuth credentials by attempting to exchange
// them for an access token using the OAuth token endpoint.
//
// Validation approach:
//   - Constructs URL: {hostname}/oauth/token (defaults to https://gitlab.com/oauth/token)
//   - Sends HTTP POST with client_id, client_secret, grant_type=authorization_code, and dummy code
//   - 400 Bad Request = valid credentials (invalid authorization code is expected)
//   - 401 Unauthorized = invalid credentials
//
// Note: We use a dummy authorization code because we only want to validate the client credentials,
// not actually obtain an access token. GitLab returns 400 for invalid codes but 401 for invalid credentials.
type OAuthCredentialsValidator struct {
	validator *simplevalidate.Validator[OAuthCredentials]
}

// NewOAuthCredentialsValidator creates a new GitLab OAuth credentials validator
func NewOAuthCredentialsValidator() *OAuthCredentialsValidator {
	return &OAuthCredentialsValidator{
		validator: &simplevalidate.Validator[OAuthCredentials]{
			EndpointFunc: func(secret OAuthCredentials) (string, error) {
				// Validation requires both client_id and client_secret
				if secret.ClientID == "" || secret.ClientSecret == "" {
					return "", errors.New("both ClientID and ClientSecret are required for validation")
				}

				// Determine the hostname to use
				hostname := secret.Hostname
				if hostname == "" {
					return gitlabOAuthEndpoint, nil
				}

				// Add scheme if not present
				if !strings.HasPrefix(hostname, "http://") && !strings.HasPrefix(hostname, "https://") {
					// Use http for localhost/127.0.0.1 (testing), https otherwise
					if strings.HasPrefix(hostname, "127.0.0.1:") || strings.HasPrefix(hostname, "localhost:") {
						hostname = "http://" + hostname
					} else {
						hostname = "https://" + hostname
					}
				}

				// Construct the OAuth token endpoint URL
				return strings.TrimSuffix(hostname, "/") + "/oauth/token", nil
			},
			HTTPMethod: http.MethodPost,
			Body: func(secret OAuthCredentials) (string, error) {
				// Prepare form data with dummy authorization code
				formData := url.Values{
					"client_id":     {secret.ClientID},
					"client_secret": {secret.ClientSecret},
					"code":          {dummyAuthCode},
					"grant_type":    {"authorization_code"},
					"redirect_uri":  {dummyRedirectURI},
				}
				return formData.Encode(), nil
			},
			HTTPHeaders: func(secret OAuthCredentials) map[string]string {
				return map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				}
			},
			ValidResponseCodes:   []int{http.StatusBadRequest},
			InvalidResponseCodes: []int{http.StatusUnauthorized},
			HTTPC:                &http.Client{Timeout: httpClientTimeout},
		},
	}
}

// Validate checks if the GitLab OAuth credentials are valid by attempting to use them
// at the OAuth token endpoint.
//
// Returns:
//   - veles.ValidationStatusValid: Credentials are valid (400 Bad Request with invalid grant)
//   - veles.ValidationStatusInvalid: Credentials are invalid (401 Unauthorized)
//   - error: Network errors or other validation failures
func (v *OAuthCredentialsValidator) Validate(ctx context.Context, secret OAuthCredentials) (veles.ValidationStatus, error) {
	return v.validator.Validate(ctx, secret)
}
