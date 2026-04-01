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

package dropboxappaccesstoken

import (
	"net/http"
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// dropboxAPIBaseURL is the Dropbox API v2 base URL.
	dropboxAPIBaseURL = "https://api.dropboxapi.com"
	// validationTimeout is the timeout for API validation requests.
	validationTimeout = 10 * time.Second
	// GetCurrentAccountEndpoint is the Dropbox API endpoint for getting the
	// current user's account information. This is a read-only endpoint that
	// verifies the token is valid without modifying any data.
	// Reference: https://www.dropbox.com/developers/documentation/http/documentation#users-get_current_account
	GetCurrentAccountEndpoint = "/2/users/get_current_account"
)

// NewValidator creates a new Validator that validates Dropbox access tokens by
// making a test request to the Dropbox API /2/users/get_current_account endpoint.
// A POST request with a valid Bearer token returns 200 OK.
// An invalid token returns 401 Unauthorized.
func NewValidator() *sv.Validator[AccessToken] {
	return &sv.Validator[AccessToken]{
		Endpoint:   dropboxAPIBaseURL + GetCurrentAccountEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(t AccessToken) map[string]string {
			return map[string]string{"Authorization": "Bearer " + t.Token}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusTooManyRequests},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
