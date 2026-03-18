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
	"net/http"
	"strings"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	defaultGitlabJobAPIPath = "/api/v4/job"
)

// NewCIJobTokenValidator creates a new Validator for GitLab CI/CD Job Tokens via the GitLab API endpoint.
//
// It performs a GET request to the job endpoint using the Job Token in the JOB-TOKEN header.
// If a hostname is found with the token, it validates against that instance (e.g., self-hosted GitLab).
// Otherwise, it defaults to gitlab.com. If the request returns HTTP 200, the token is considered valid.
// If 401 Unauthorized, the token is invalid. Other errors return ValidationFailed.
func NewCIJobTokenValidator() *simplevalidate.Validator[CIJobToken] {
	return &simplevalidate.Validator[CIJobToken]{
		EndpointFunc: func(secret CIJobToken) (string, error) {
			hostname := secret.Hostname
			if hostname == "" {
				hostname = "gitlab.com"
			}
			// Check if hostname already includes protocol
			// The detector extracts only the hostname without protocol, but tests may pass full URLs
			endpoint := hostname
			if !strings.HasPrefix(hostname, "http://") && !strings.HasPrefix(hostname, "https://") {
				endpoint = "https://" + hostname
			}
			return endpoint + defaultGitlabJobAPIPath, nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(secret CIJobToken) map[string]string {
			return map[string]string{
				"Job-Token": secret.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC:                &http.Client{Timeout: validationTimeout},
	}
}
