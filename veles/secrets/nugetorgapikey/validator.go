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

package nugetorgapikey

import (
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewValidator creates a new Validator that validates NuGet.org API keys via
// the NuGet.org package push endpoint.
//
// It performs a PUT request to the NuGet.org package publish endpoint
// using the API key in the X-Nuget-Apikey header. If the request returns
// HTTP 400 Bad Request, the key is valid (authentication passed, but no
// package body was provided). If 403 Forbidden, the key is valid but has
// limited scope. If 401 Unauthorized, the key is invalid. Other status codes
// will result in ValidationFailed.
func NewValidator() *simplevalidate.Validator[NuGetOrgAPIKey] {
	return &simplevalidate.Validator[NuGetOrgAPIKey]{
		Endpoint:   "https://www.nuget.org/api/v2/package",
		HTTPMethod: http.MethodPut,
		HTTPHeaders: func(key NuGetOrgAPIKey) map[string]string {
			return map[string]string{
				"X-Nuget-Apikey": key.Key,
				"Content-Type":   "application/octet-stream",
			}
		},
		ValidResponseCodes:   []int{http.StatusBadRequest, http.StatusForbidden},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
