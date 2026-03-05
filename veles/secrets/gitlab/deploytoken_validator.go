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

package gitlab

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
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
// The validator makes a GET request to:
// https://{hostname}/{namespace}/{project}.git/info/refs?service=git-upload-pack
//
// Expected responses:
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

				// Construct the validation endpoint URL
				// Format: https://{hostname}/{namespace}/{project}.git/info/refs?service=git-upload-pack
				// Example: https://gitlab.com/mygroup/myproject.git/info/refs?service=git-upload-pack
				return fmt.Sprintf(
					"https://%s/%s/%s.git/info/refs?service=git-upload-pack",
					info.Host,
					info.Namespace,
					info.Project,
				), nil
			},
			// HTTPMethod specifies the HTTP method for the validation request.
			// Git uses GET for info/refs requests.
			HTTPMethod: http.MethodGet,
			// HTTPHeaders sets up Basic Authentication using the deploy token credentials.
			// GitLab expects the Authorization header in the format: "Basic base64(username:token)"
			HTTPHeaders: func(secret DeployToken) map[string]string {
				return map[string]string{
					"Authorization": "Basic " + basicAuth(secret.Username, secret.Token),
				}
			},
			// Use a custom HTTP client with timeout instead of a dedicated timeout field.
			HTTPC: &http.Client{Timeout: 10 * time.Second},
			// Response codes that indicate a valid token.
			ValidResponseCodes:   []int{http.StatusOK, http.StatusForbidden},
			InvalidResponseCodes: []int{http.StatusUnauthorized},
		},
	}
}

// Validate checks if the GitLab Deploy Token is valid by attempting to access the repository.
// Returns:
//   - veles.ValidationStatusValid: Token is valid (200 OK or 403 Forbidden)
//   - veles.ValidationStatusInvalid: Token is invalid (401 Unauthorized)
//   - error: Network errors or other validation failures
func (v *DeployTokenValidator) Validate(ctx context.Context, secret DeployToken) (veles.ValidationStatus, error) {
	status, err := v.validator.Validate(ctx, secret)
	return status, err
}

// basicAuth encodes username and password in the format required for HTTP Basic Authentication.
// Returns base64-encoded string of "username:password"
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
