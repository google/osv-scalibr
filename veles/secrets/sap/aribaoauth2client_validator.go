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
	"encoding/base64"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewSAPAribaOAuth2ClientCredentialsValidator creates a new SAP Ariba OAuth2 Client Credentials Validator.
//
// It performs a POST request to the SAP Ariba OAuth2 token endpoint.
// If the request returns HTTP 200, the credentials are valid.
// If 401 Unauthorized, they are invalid.
func NewSAPAribaOAuth2ClientCredentialsValidator() *sv.Validator[AribaOAuth2ClientCredentials] {
	return &sv.Validator[AribaOAuth2ClientCredentials]{
		Endpoints:  []string{"https://api.ariba.com/v2/oauth/token", "https://api-eu.ariba.com/v2/oauth/token", "https://api.ariba.cn/v2/oauth/token", "https://api.mn1.ariba.com/v2/oauth/token", "https://api.mn2.ariba.com/v2/oauth/token", "https://api.au.cloud.ariba.com/v2/oauth/token", "https://api.jp.cloud.ariba.com/v2/oauth/token"},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(creds AribaOAuth2ClientCredentials) map[string]string {
			raw := creds.ID + ":" + creds.Secret
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))
			return map[string]string{
				"Authorization": "Basic " + encoded,
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		Body: func(creds AribaOAuth2ClientCredentials) (string, error) {
			return "grant_type=client_credentials", nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
