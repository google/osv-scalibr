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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

var (
	_ veles.Validator[PipelineTriggerToken] = &PipelineTriggerTokenValidator{}
)

// PipelineTriggerTokenValidator validates GitLab Pipeline Trigger Tokens by attempting to
// trigger a pipeline using the GitLab API.
//
// Validation approach:
//   - Constructs URL: https://{hostname}/api/v4/projects/{project_id}/trigger/pipeline
//   - Sends HTTP POST with form data: token={token}&ref={ref}
//   - 201 Created = valid token with permissions to trigger pipeline
//   - 400 Bad Request with "Reference not found" = valid token but invalid ref
//   - 404 Not Found = invalid token or no access to project
//   - 401 Unauthorized = invalid token
type PipelineTriggerTokenValidator struct {
	*simplevalidate.Validator[PipelineTriggerToken]
}

// NewPipelineTriggerTokenValidator creates a new GitLab Pipeline Trigger Token validator
func NewPipelineTriggerTokenValidator() *PipelineTriggerTokenValidator {
	return &PipelineTriggerTokenValidator{
		Validator: &simplevalidate.Validator[PipelineTriggerToken]{
			// EndpointFunc constructs the validation URL from the hostname and project ID.
			// This endpoint is the GitLab API endpoint for triggering pipelines.
			EndpointFunc: func(secret PipelineTriggerToken) (string, error) {
				// Validation requires a project ID to construct the endpoint
				if secret.ProjectID == "" {
					return "", errors.New("ProjectID is required for validation")
				}

				// Use the extracted hostname if available, otherwise default to gitlab.com
				hostname := secret.Hostname
				if hostname == "" {
					hostname = "gitlab.com"
				}

				// Format: https://{hostname}/api/v4/projects/{project_id}/trigger/pipeline
				return fmt.Sprintf("https://%s/api/v4/projects/%s/trigger/pipeline",
					hostname, secret.ProjectID), nil
			},
			HTTPMethod: http.MethodPost,
			// HTTPHeaders sets the Content-Type for form data
			HTTPHeaders: func(secret PipelineTriggerToken) map[string]string {
				return map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				}
			},
			// Body constructs the form data with token and ref
			Body: func(secret PipelineTriggerToken) (string, error) {
				// Use a random non-existent ref to avoid actually triggering pipelines
				// This allows us to validate the token without side effects
				ref := "randomfffffffff"

				// Construct form data
				data := url.Values{}
				data.Set("token", secret.Token)
				data.Set("ref", ref)
				return data.Encode(), nil
			},
			// ValidResponseCodes: 201 indicates successful pipeline trigger (valid token)
			// 400 with specific error message also indicates valid token but invalid ref
			ValidResponseCodes: []int{http.StatusCreated},
			// InvalidResponseCodes: 404 and 401 indicate invalid token
			// - 404 Not Found: Token doesn't exist or no access to project
			// - 401 Unauthorized: Invalid token
			InvalidResponseCodes: []int{http.StatusNotFound, http.StatusUnauthorized},
			// StatusFromResponseBody handles the 400 Bad Request case
			// 400 with "Reference not found" means the token is valid but the ref doesn't exist
			StatusFromResponseBody: func(body io.Reader) (veles.ValidationStatus, error) {
				bodyBytes, err := io.ReadAll(body)
				if err != nil {
					return veles.ValidationFailed, err
				}
				bodyStr := string(bodyBytes)

				// Check if the error is "Reference not found"
				if strings.Contains(bodyStr, "Reference not found") || strings.Contains(bodyStr, "base") {
					// Token is valid, but the ref doesn't exist
					// This is still considered a valid token
					return veles.ValidationValid, nil
				}
				// Other errors indicate invalid token or other issues
				return veles.ValidationInvalid, nil
			},
			HTTPC: &http.Client{
				Timeout: 10 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
		},
	}
}

// Validate checks if the GitLab Pipeline Trigger Token is valid by attempting to
// trigger a pipeline using the GitLab API.
//
// Returns:
//   - veles.ValidationValid: Token is valid (201 Created or 400 with "Reference not found")
//   - veles.ValidationInvalid: Token is invalid (404 Not Found or 401 Unauthorized)
//   - error: Network errors or other validation failures
func (v *PipelineTriggerTokenValidator) Validate(ctx context.Context, secret PipelineTriggerToken) (veles.ValidationStatus, error) {
	return v.Validator.Validate(ctx, secret)
}
