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

package sap

import (
	"net/http"
	"net/url"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewSAPConcurRefreshTokenValidator creates a new SAP Concur Refresh Token Validator.
//
// It performs a POST request to the SAP Concur OAuth2 token validation endpoint.
// If the request returns HTTP 200, the credentials are valid.
// If 401 Unauthorized, they are invalid.
func NewSAPConcurRefreshTokenValidator() *sv.Validator[ConcurRefreshToken] {
	return &sv.Validator[ConcurRefreshToken]{
		Endpoints:  []string{"https://apj1.api.concursolutions.com/oauth2/v0/token", "https://www-apj1.api.concursolutions.com/oauth2/v0/token", "https://usg.api.concursolutions.com/oauth2/v0/token", "https://www-usg.api.concursolutions.com/oauth2/v0/token", "https://eu2.api.concursolutions.com/oauth2/v0/token", "https://www-eu2.api.concursolutions.com/oauth2/v0/token", "https://glz.api.concursolutions.com/oauth2/v0/token", "https://us2.api.concursolutions.com/oauth2/v0/token", "https://www-us2.api.concursolutions.com/oauth2/v0/token", "https://us-impl.api.concursolutions.com/oauth2/v0/token", "https://www-us-impl.api.concursolutions.com/oauth2/v0/token", "https://emea-impl.api.concursolutions.com/oauth2/v0/token", "https://www-emea-impl.api.concursolutions.com/oauth2/v0/token", "https://www.concursolutions.com/oauth2/v0/token", "https://eu1.concursolutions.com/oauth2/v0/token", "https://implementation.concursolutions.com/oauth2/v0/token", "https://eu1imp.concursolutions.com/oauth2/v0/token", "https://us.api.concursolutions.com/oauth2/v0/token"},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(creds ConcurRefreshToken) map[string]string {
			return map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}
		},
		Body: func(creds ConcurRefreshToken) (string, error) {
			form := url.Values{}
			form.Set("client_id", creds.ID)
			form.Set("client_secret", creds.Secret)
			form.Set("grant_type", "refresh_token")
			form.Set("refresh_token", creds.Token)

			return form.Encode(), nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
