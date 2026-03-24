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

package salesforceoauth2refresh

import (
	"encoding/base64"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewValidator creates a new Salesforce OAuth Client Credentials Validator.
//
// It performs a POST request to the Salesforce App token endpoint.
// If the request returns HTTP 200, the credentials are valid.
// If 401 Unauthorized, they are invalid.
func NewValidator() *sv.Validator[Credentials] {
	return &sv.Validator[Credentials]{
		Endpoint: "https://login.salesforce.com/services/oauth2/token",
		Body: func(creds Credentials) (string, error) {
			// Salesforce requires refresh token in body
			return "refresh_token=" + creds.Refresh, nil
		},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(creds Credentials) map[string]string {
			raw := creds.ID + ":" + creds.Secret
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))
			return map[string]string{
				"Authorization": "Basic " + encoded,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
