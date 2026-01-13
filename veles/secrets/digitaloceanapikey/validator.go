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

package digitaloceanapikey

import (
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewValidator creates a new Validator that validates DigitalOcean API keys via
// the DigitalOcean API endpoint.
//
// It performs a GET request to the DigitalOcean account endpoint
// using the API key in the Authorization header. HTTP 200, the key is considered valid.
// If 403, the key is considered valid with limited scope(fine tuned),
// If 401 Unauthorized, the key is invalid. Other status codes will result in ValidationFailed.
func NewValidator() *simplevalidate.Validator[DigitaloceanAPIToken] {
	return &simplevalidate.Validator[DigitaloceanAPIToken]{
		Endpoint:   "http://api.digitalocean.com/v2/account",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(key DigitaloceanAPIToken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + key.Key,
				"Content-Type":  "application/json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK, http.StatusForbidden},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
