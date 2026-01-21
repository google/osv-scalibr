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

package bitwardenapikey

import (
	"net/http"
	"net/url"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	bitwardenIdentityEndpoint = "https://identity.bitwarden.com/connect/token"
)

// NewValidator creates a new Validator that validates the BitwardenAPIKey via
// the Bitwarden Identity Server.
//
// It performs a POST request to the token endpoint.
// - 200 OK: Valid Secret.
// - 400 Bad Request / 401 Unauthorized: Invalid Secret.
func NewValidator() *sv.Validator[BitwardenAPIKey] {
	return &sv.Validator[BitwardenAPIKey]{
		Endpoint:   bitwardenIdentityEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(s BitwardenAPIKey) map[string]string {
			return map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}
		},
		Body: func(s BitwardenAPIKey) (string, error) {
			data := url.Values{}
			data.Set("grant_type", "client_credentials")
			data.Set("scope", "api")
			data.Set("client_id", s.ClientID)
			data.Set("client_secret", s.ClientSecret)
			data.Set("deviceIdentifier", "0")
			data.Set("deviceType", "0")
			data.Set("deviceName", "scalibr")
			return data.Encode(), nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusBadRequest, http.StatusUnauthorized},
	}
}
