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

package salesforceoauth

import (
	"encoding/base64"
	"net/http"
	"net/url"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	salesforceTokenEndpoint = "https://login.salesforce.com/services/oauth2/token"
)

// NewValidator creates a new Validator that validates the Salesforce OAuth credentials.
//
// It performs a POST request to the token endpoint.
// - 200 OK: Valid Secret.
// - 400 Bad Request / 401 Unauthorized: Invalid Secret.
func NewValidator() *sv.Validator[Credentials] {
	return &sv.Validator[Credentials]{
		Endpoint:   salesforceTokenEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(s Credentials) map[string]string {
			auth := base64.StdEncoding.EncodeToString([]byte(s.ClientID + ":" + s.ClientSecret))
			return map[string]string{
				"Authorization": "Basic " + auth,
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		Body: func(s Credentials) (string, error) {
			data := url.Values{}
			data.Set("grant_type", "client_credentials")
			return data.Encode(), nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusBadRequest, http.StatusUnauthorized},
	}
}
