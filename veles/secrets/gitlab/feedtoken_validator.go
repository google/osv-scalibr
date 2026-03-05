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
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewFeedTokenValidator creates a new Validator for GitLab Feed Tokens.
// It performs a GET request to the GitLab dashboard projects atom feed endpoint
// at https://{hostname}/dashboard/projects.atom?feed_token={token}.
// If the request returns HTTP 200, the token is considered valid.
// If 401 Unauthorized or 403 Forbidden, the token is invalid.
// Other errors return ValidationFailed.
//
// If the hostname is empty, it defaults to gitlab.com.
//
// Reference: https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#feed-token
func NewFeedTokenValidator() *simplevalidate.Validator[FeedToken] {
	return &simplevalidate.Validator[FeedToken]{
		EndpointFunc: func(secret FeedToken) (string, error) {
			// Default to gitlab.com if no hostname is provided
			hostname := secret.Hostname
			if hostname == "" {
				hostname = "gitlab.com"
			}
			// Construct the validation URL with the hostname and token
			// Format: https://{hostname}/dashboard/projects.atom?feed_token={token}
			return fmt.Sprintf("https://%s/dashboard/projects.atom?feed_token=%s",
				hostname, secret.Token), nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(secret FeedToken) map[string]string {
			return map[string]string{
				"Accept": "application/atom+xml",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
	}
}
