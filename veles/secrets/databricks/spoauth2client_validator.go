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
	"errors"
	"fmt"
	"net/http"
	"net/url"

	nv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewSPOAuth2ClientValidator creates a new Databricks Service Principal OAuth2 Client Credentials Validator.
// It performs GET requests to the Databricks endpoints with discovered credentials.
//
// Validation logic:
// - HTTP Status 200: Token is valid and authenticated
// - HTTP Status 401: Token is invalid
// - Other status codes: Validation failed
// Reference:
// https://docs.databricks.com/aws/en/dev-tools/auth/oauth-m2m
func NewSPOAuth2ClientValidator() *nv.Validator[SPOAuth2ClientCredentials] {
	return &nv.Validator[SPOAuth2ClientCredentials]{
		EndpointFunc: func(creds SPOAuth2ClientCredentials) (string, error) {
			if creds.URL == "" {
				return "", errors.New("OAuth2 url is empty")
			}
			return fmt.Sprintf("https://%s/oidc/v1/token", creds.URL), nil
		},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(creds SPOAuth2ClientCredentials) map[string]string {
			raw := creds.ID + ":" + creds.Secret
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))
			return map[string]string{
				"Authorization": "Basic " + encoded,
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		Body: func(creds SPOAuth2ClientCredentials) (string, error) {
			form := url.Values{}
			form.Set("grant_type", "client_credentials")
			form.Set("scope", "all-apis")

			return form.Encode(), nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
