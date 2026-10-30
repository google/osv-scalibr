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
	"errors"
	"net/http"
	"strings"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewBTPOAuth2ClientCredentialsValidator creates a new SAP BTP / BTP XSUAA OAuth2 Client Credentials Validator.
//
// It performs a POST request to the SAP token endpoint.
// If the request returns HTTP 200, the credentials are valid.
// If 401 Unauthorized, they are invalid.
func NewBTPOAuth2ClientCredentialsValidator() *sv.Validator[BTPOAuth2ClientCredentials] {
	return &sv.Validator[BTPOAuth2ClientCredentials]{
		EndpointFunc: func(creds BTPOAuth2ClientCredentials) (string, error) {
			tokenURL := creds.TokenURL
			if tokenURL == "" {
				return "", errors.New("URL is empty")
			}

			if !strings.HasSuffix(tokenURL, "/oauth/token") {
				tokenURL += "/oauth/token"
			}
			return "https://" + tokenURL, nil
		},
		Body: func(creds BTPOAuth2ClientCredentials) (string, error) {
			// SAP requires grant_type in body for client_credentials
			return "grant_type=client_credentials", nil
		},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(creds BTPOAuth2ClientCredentials) map[string]string {
			raw := creds.ID + ":" + creds.Secret
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))
			return map[string]string{
				"Authorization": "Basic " + encoded,
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
