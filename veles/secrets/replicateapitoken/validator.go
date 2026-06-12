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

package replicateapitoken

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type rat = ReplicateAPIToken

// NewValidator creates a new Replicate API token Validator.
// It performs a GET request to the Replicate account endpoint
// (https://api.replicate.com/v1/account) using the API token in the
// Authorization header with the "Token" scheme. If the request returns HTTP
// 200, the token is considered valid. If 401 Unauthorized, the token is
// invalid. Other errors return ValidationFailed.
func NewValidator() *sv.Validator[rat] {
	return &sv.Validator[rat]{
		Endpoint:   "https://api.replicate.com/v1/account",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s rat) map[string]string {
			return map[string]string{"Authorization": "Token " + s.Key}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
