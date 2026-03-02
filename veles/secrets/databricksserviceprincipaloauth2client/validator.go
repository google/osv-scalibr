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

package databricksserviceprincipaloauth2client

import (
	"errors"
	"fmt"
	"net/http"

	nv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewValidator creates a new Databricks Service Principal OAuth2 Client Credentials Validator.
// It performs POST requests to the Databricks endpoints
// with discovered credentials.
//
// Validation logic:
// - HTTP Status 200, 403, and 404: Token is valid and authenticated
// - HTTP Status 400 and 401: Token is invalid
// - Other status codes: Validation failed
// See the error codes here:
// https://docs.databricks.com/api/gcp/workspace/tokenmanagement/createobotoken
func NewValidator() *nv.Validator[Credentials] {
	return &nv.Validator[Credentials]{
		EndpointFunc: func(creds Credentials) (string, error) {
			if creds.URL == "" {
				return "", errors.New("OAuth2 url is empty")
			}
			return fmt.Sprintf("https://%s/api/2.0/token/create", creds.URL), nil
		},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(creds Credentials) map[string]string {
			return map[string]string{
				"client_id":     creds.ID,
				"client_secret": creds.Secret,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusBadRequest},
	}
}
