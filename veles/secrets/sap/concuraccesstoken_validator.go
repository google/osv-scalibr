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

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewSAPConcurAccessTokenValidator creates a new SAP Concur Access Token Validator.
//
// It performs a GET request to the SAP Concur token validation endpoint.
// If the request returns HTTP 200, the credentials are valid.
// If 401 Unauthorized, they are invalid.
// Reference:
// https://developer.concur.com/api-reference/authentication/getting-started.html
// https://developer.concur.com/platform/base-uris.html
func NewSAPConcurAccessTokenValidator() *sv.Validator[ConcurAccessToken] {
	return &sv.Validator[ConcurAccessToken]{
		Endpoints:  []string{"https://apj1.api.concursolutions.com/profile/v1/me", "https://www-apj1.api.concursolutions.com/profile/v1/me", "https://usg.api.concursolutions.com/profile/v1/me", "https://www-usg.api.concursolutions.com/profile/v1/me", "https://eu2.api.concursolutions.com/profile/v1/me", "https://www-eu2.api.concursolutions.com/profile/v1/me", "https://glz.api.concursolutions.com/profile/v1/me", "https://us2.api.concursolutions.com/profile/v1/me", "https://www-us2.api.concursolutions.com/profile/v1/me", "https://us-impl.api.concursolutions.com/profile/v1/me", "https://www-us-impl.api.concursolutions.com/profile/v1/me", "https://emea-impl.api.concursolutions.com/profile/v1/me", "https://www-emea-impl.api.concursolutions.com/profile/v1/me", "https://www.concursolutions.com/profile/v1/me", "https://eu1.concursolutions.com/profile/v1/me", "https://implementation.concursolutions.com/profile/v1/me", "https://eu1imp.concursolutions.com/profile/v1/me", "https://us.api.concursolutions.com/profile/v1/me"},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(creds ConcurAccessToken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + creds.Token,
				"Accept":        "application/json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
