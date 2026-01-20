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

package github

import (
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewOAuthTokenValidator creates a new Validator that validates Github OAuth
// token via the Github API endpoint.
func NewOAuthTokenValidator() *simplevalidate.Validator[OAuthToken] {
	return &simplevalidate.Validator[OAuthToken]{
		Endpoint:   githubAPIBaseURL + UserValidationEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k OAuthToken) map[string]string {
			return apiHeaders(k.Token)
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusForbidden},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
