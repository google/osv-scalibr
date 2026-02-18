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

package bitwardenoauth2access

import (
	"net/http"
	"net/url"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type token = Token

// NewValidator creates a new Bitwarden OAuth2 access token Validator.
// It performs a POST request to the Bitwarden identity token endpoint
// using client_credentials grant type with the extracted client ID and secret.
// If the request returns HTTP 200, the credentials are valid.
// If 400 Bad Request or 401 Unauthorized, the credentials are invalid.
//
// See: https://bitwarden.com/help/public-api/#authentication
func NewValidator() *sv.Validator[token] {
	return &sv.Validator[token]{
		Endpoint:   "https://identity.bitwarden.com/connect/token",
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(s token) map[string]string {
			return map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}
		},
		Body: func(s token) (string, error) {
			data := url.Values{}
			data.Set("grant_type", "client_credentials")
			data.Set("scope", "api")
			data.Set("client_id", "user."+s.ClientID)
			data.Set("client_secret", s.ClientSecret)
			data.Set("deviceName", "fireFox")
			data.Set("twoFactorToken", "0")
			data.Set("deviceIdentifier", "0")
			data.Set("deviceType", "0")
			return data.Encode(), nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusBadRequest, http.StatusUnauthorized},
	}
}
