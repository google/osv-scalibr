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
	"fmt"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

var (
	_ veles.Validator[RunnerAuthToken] = &RunnerAuthTokenValidator{}
)

// RunnerAuthTokenValidator validates GitLab Runner authentication tokens
// by sending a POST request to the GitLab runners verify endpoint.
type RunnerAuthTokenValidator struct {
	validator *simplevalidate.Validator[RunnerAuthToken]
}

// NewRunnerAuthTokenValidator creates a new GitLab Runner authentication token validator.
func NewRunnerAuthTokenValidator() *RunnerAuthTokenValidator {
	return &RunnerAuthTokenValidator{
		validator: &simplevalidate.Validator[RunnerAuthToken]{
			EndpointFunc: func(secret RunnerAuthToken) (string, error) {
				hostname := secret.Hostname
				if hostname == "" {
					hostname = "gitlab.com"
				}
				return fmt.Sprintf("https://%s/api/v4/runners/verify", hostname), nil
			},
			HTTPMethod: http.MethodPost,
			Body: func(k RunnerAuthToken) (string, error) {
				return fmt.Sprintf(`{"token":"%s"}`, k.Token), nil
			},
			HTTPHeaders: func(k RunnerAuthToken) map[string]string {
				return map[string]string{
					"Content-Type": "application/json",
				}
			},
			ValidResponseCodes:   []int{http.StatusOK},
			InvalidResponseCodes: []int{http.StatusForbidden},
			HTTPC: &http.Client{
				Timeout: 10 * time.Second,
			},
		},
	}
}

// Validate checks if the GitLab Runner authentication token is valid.
//
// Returns:
//   - veles.ValidationStatusValid: Token is valid (200 OK)
//   - veles.ValidationStatusInvalid: Token is invalid (403 Forbidden)
//   - error: Network errors or other validation failures
func (v *RunnerAuthTokenValidator) Validate(ctx context.Context, secret RunnerAuthToken) (veles.ValidationStatus, error) {
	return v.validator.Validate(ctx, secret)
}
