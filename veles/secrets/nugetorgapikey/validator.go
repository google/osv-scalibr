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

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

type pak = NuGetOrgAPIKey

// NewValidator checks whether the given NuGetOrgAPIKey is valid.
//
// It performs a PUT request to the NuGet.org package push endpoint
// using the API key in the X-NuGet-ApiKey header. If the request returns
// HTTP 400 (Bad Request), the key is considered valid (the key is authenticated
// but no package body was provided). If 401 Unauthorized or 403 Forbidden,
// the key is invalid.
func NewValidator() *sv.Validator[pak] {
	return &sv.Validator[pak]{
		Endpoint:   "https://www.nuget.org/api/v2/package",
		HTTPMethod: http.MethodPut,
		HTTPHeaders: func(s pak) map[string]string {
			return map[string]string{"X-NuGet-ApiKey": s.Token}
		},
		ValidResponseCodes:   []int{http.StatusBadRequest},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
	}
}
