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
	// Dropbox API base URL.
	dropboxAPIBaseURL = "https://api.dropboxapi.com"
	// Timeout for API validation requests.
	validationTimeout = 10 * time.Second
	// AccountEndpoint is the Dropbox get current account API endpoint.
	AccountEndpoint = "/2/users/get_current_account"
)

// NewValidator creates a new Validator that validates Dropbox App access tokens
// by making a POST request to the Dropbox API /2/users/get_current_account endpoint.
func NewValidator() *sv.Validator[APIAccessToken] {
	v := &sv.Validator[APIAccessToken]{
		Endpoint:   dropboxAPIBaseURL + AccountEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(k APIAccessToken) map[string]string {
			return map[string]string{"Authorization": "Bearer " + k.Token}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusTooManyRequests},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}

	return v
}
