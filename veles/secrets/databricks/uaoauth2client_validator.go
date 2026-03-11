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

package databricks

import (
	"encoding/base64"
	"net/http"
	"net/url"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewUAOAuth2ClientValidator creates a new Databricks User Account OAuth2 Client Credentials Validator.
// It performs POST requests to the Databricks endpoints with discovered credentials.
//
// Validation logic:
// - HTTP Status 200: Token is valid and authenticated
// - HTTP Status 401: Token is invalid
// - Other status codes: Validation failed
// Reference:
// https://docs.databricks.com/aws/en/dev-tools/auth/oauth-m2m
func NewUAOAuth2ClientValidator() *sv.Validator[UAOAuth2ClientCredentials] {
	return &sv.Validator[UAOAuth2ClientCredentials]{
		EndpointsFunc: func(creds UAOAuth2ClientCredentials) ([]string, error) {
			return []string{
				"https://accounts.cloud.databricks.com/oidc/accounts/" + creds.AccountID + "/v1/token",
				"https://accounts.gcp.databricks.com/oidc/accounts/" + creds.AccountID + "/v1/token",
				"https://accounts.azuredatabricks.net/oidc/accounts/" + creds.AccountID + "/v1/token",
			}, nil
		},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(creds UAOAuth2ClientCredentials) map[string]string {
			raw := creds.ID + ":" + creds.Secret
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))
			return map[string]string{
				"Authorization": "Basic " + encoded,
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		Body: func(creds UAOAuth2ClientCredentials) (string, error) {
			form := url.Values{}
			form.Set("grant_type", "client_credentials")
			form.Set("scope", "all-apis")

			return form.Encode(), nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
