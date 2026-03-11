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
	"errors"
	"fmt"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewSPPATValidator creates a new Databricks Service Principal PAT credentials Validator.
// It performs GET requests to the Databricks endpoints with discovered credentials.
//
// Validation logic:
// - HTTP Status 200: Token is valid and authenticated
// - HTTP Status 401: Token is invalid
// - Other status codes: Validation failed
// See the error codes here:
// https://docs.databricks.com/api/gcp/workspace/tokenmanagement/createobotoken
// https://docs.databricks.com/api/gcp/workspace/tokens/list
func NewSPPATValidator() *sv.Validator[SPPATCredentials] {
	return &sv.Validator[SPPATCredentials]{
		EndpointFunc: func(creds SPPATCredentials) (string, error) {
			if creds.Token == "" || creds.URL == "" {
				return "", errors.New("OAuth2 token or url is empty")
			}
			return fmt.Sprintf("https://%s/api/2.0/token/list", creds.URL), nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(creds SPPATCredentials) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + creds.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusForbidden},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
