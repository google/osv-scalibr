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
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
	gitlabcommon "github.com/google/osv-scalibr/veles/secrets/common/gitlab"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

var (
	_ veles.Validator[DeployToken] = &DeployTokenValidator{}
)

// DeployTokenValidator validates GitLab Deploy Tokens by attempting to access the repository's
// info/refs endpoint, which is the same endpoint used by Git clients during clone/fetch.
// This validates both token authenticity and repository access permissions.
//
// Validation approach:
//   - Constructs URL: {scheme}://{hostname}/{namespace}/{project}.git/info/refs?service=git-upload-pack
//   - Sends HTTP GET with Basic Auth (username:token)
//   - 200 OK = valid token with read access
//   - 403 Forbidden = valid token but no access to this repo
//   - 401 Unauthorized = invalid token or credentials
type DeployTokenValidator struct {
	validator *simplevalidate.Validator[DeployToken]
}

// NewDeployTokenValidator creates a new GitLab Deploy Token validator
func NewDeployTokenValidator() *DeployTokenValidator {
	return &DeployTokenValidator{
		validator: &simplevalidate.Validator[DeployToken]{
			// EndpointFunc constructs the validation URL from the repository URL.
			// This endpoint (info/refs?service=git-upload-pack) is the same one Git clients
			// use during clone/fetch operations, making it ideal for validation.
			EndpointFunc: func(secret DeployToken) (string, error) {
				// Validation requires a repository URL to construct the endpoint
				if secret.RepoURL == "" {
					return "", errors.New("RepoURL is required for validation")
				}

				// Parse the repository URL to extract hostname, namespace (group), and project.
				// Supports both HTTPS (https://gitlab.com/group/project.git) and
				// SSH (git@gitlab.com:group/project.git) formats.
				info := gitlabcommon.ParseRepoURL(secret.RepoURL)
				if info == nil {
					return "", fmt.Errorf("failed to parse repository URL: %q", secret.RepoURL)
				}

				// Determine the appropriate scheme (http vs https).
				// For production GitLab instances, use https.
				// For localhost/127.0.0.1 (testing), use http.
				scheme := info.Scheme
				if scheme == "https" || scheme == "http" {
					// Keep the original scheme, but override for localhost testing
					if strings.HasPrefix(info.Host, "127.0.0.1:") || strings.HasPrefix(info.Host, "localhost:") {
						scheme = "http"
					}
				} else {
					// For git/ssh schemes, default to https for production
					scheme = "https"
					if strings.HasPrefix(info.Host, "127.0.0.1:") || strings.HasPrefix(info.Host, "localhost:") {
						scheme = "http"
					}
				}

				// Construct the GitLab repository validation URL.
				// This endpoint returns Git protocol information and requires authentication.
				// Format: {scheme}://{hostname}/{namespace}/{project}.git/info/refs?service=git-upload-pack
				return fmt.Sprintf("%s://%s/%s/%s.git/info/refs?service=git-upload-pack",
					scheme, info.Host, info.Namespace, info.Project), nil
			},
			HTTPMethod: http.MethodGet,
			// HTTPHeaders sets up Basic Authentication using the deploy token credentials.
			// GitLab expects the Authorization header in the format: "Basic base64(username:token)"
			HTTPHeaders: func(secret DeployToken) map[string]string {
				return map[string]string{
					"Authorization": "Basic " + basicAuth(secret.Username, secret.Token),
				}
			},
			// ValidResponseCodes: Both 200 and 403 indicate the token is valid.
			// - 200 OK: Token is valid and has read access to the repository
			// - 403 Forbidden: Token is valid but lacks permissions for this specific repository
			//   (still considered valid because the token exists and is recognized by GitLab)
			ValidResponseCodes: []int{http.StatusOK, http.StatusForbidden},
			// InvalidResponseCodes: 401 indicates invalid credentials.
			// - 401 Unauthorized: Token doesn't exist or username/token combination is incorrect
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

// Validate checks if the GitLab Deploy Token is valid by attempting to access
// the repository's info/refs endpoint with the provided credentials.
//
// Returns:
//   - veles.ValidationStatusValid: Token is valid (200 OK or 403 Forbidden)
//   - veles.ValidationStatusInvalid: Token is invalid (401 Unauthorized)
//   - error: Network errors or other validation failures
func (v *DeployTokenValidator) Validate(ctx context.Context, secret DeployToken) (veles.ValidationStatus, error) {
	return v.validator.Validate(ctx, secret)
}

// basicAuth returns the base64 encoded username:password for basic auth
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
