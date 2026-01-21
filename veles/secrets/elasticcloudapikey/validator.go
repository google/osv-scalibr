// Copyright 2025 Google LLC
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

package elasticcloudapikey

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type ecak = ElasticCloudAPIKey

// NewValidator creates a new Elastic Cloud API key Validator.
// It performs a GET request to the Elastic Cloud account endpoint
// using the API key in the Authorization header. If the request returns
// HTTP 200 or 403, the key is considered valid (403 means the key is
// authenticated but lacks permissions for the resource). If 401 Unauthorized,
// the key is invalid. Other errors return ValidationFailed.
func NewValidator() *sv.Validator[ecak] {
	return &sv.Validator[ecak]{
		Endpoint:   "https://api.elastic-cloud.com/api/v1/account",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s ecak) map[string]string {
			return map[string]string{"Authorization": "ApiKey " + s.Key}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusForbidden},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
