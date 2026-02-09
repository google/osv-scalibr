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

package denopat

import (
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewUserTokenValidator creates a new validator for Deno User PATs.
//
// It performs a GET request to https://api.deno.com/user.
// If the request returns HTTP 200, the key is considered valid.
// If 401 Unauthorized, the key is invalid. Other errors return ValidationFailed.
func NewUserTokenValidator() *simplevalidate.Validator[DenoUserPAT] {
	return &simplevalidate.Validator[DenoUserPAT]{
		Endpoint:   "https://api.deno.com/user",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(pat DenoUserPAT) map[string]string {
			return map[string]string{"Authorization": "Bearer " + pat.Pat}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC:                http.DefaultClient,
	}
}

// NewOrgTokenValidator creates a new validator for Deno Organization PATs.
//
// It performs a GET request to https://api.deno.com/organization.
// If the request returns HTTP 200, the key is considered valid.
// If 401 Unauthorized, the key is invalid. Other errors return ValidationFailed.
func NewOrgTokenValidator() *simplevalidate.Validator[DenoOrgPAT] {
	return &simplevalidate.Validator[DenoOrgPAT]{
		Endpoint:   "https://api.deno.com/organization",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(pat DenoOrgPAT) map[string]string {
			return map[string]string{"Authorization": "Bearer " + pat.Pat}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC:                http.DefaultClient,
	}
}
