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
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewUAPATValidator creates a new Databricks User Account PAT credentials Validator.
// It performs GET requests to the Databricks endpoints with discovered credentials.
//
// Validation logic:
// - HTTP Status 200: Token is valid and authenticated
// - HTTP Status 401: Token is invalid
// - Other status codes: Validation failed
// See the error codes here:
// https://docs.databricks.com/api/account/accountusers/list
func NewUAPATValidator() *sv.Validator[UAPATCredentials] {
	return &sv.Validator[UAPATCredentials]{
		EndpointsFunc: func(creds UAPATCredentials) ([]string, error) {
			return []string{
				"https://accounts.cloud.databricks.com/api/2.0/accounts/" + creds.AccountID + "/scim/v2/Users",
				"https://accounts.gcp.databricks.com/api/2.0/accounts/" + creds.AccountID + "/scim/v2/Users",
				"https://accounts.azuredatabricks.net/api/2.0/accounts/" + creds.AccountID + "/scim/v2/Users",
			}, nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(creds UAPATCredentials) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + creds.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
