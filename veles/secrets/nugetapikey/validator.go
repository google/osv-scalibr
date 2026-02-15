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

package nugetapikey

import (
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// API endpoint for package upload.
	// We use PUT /api/v2/package with X-NuGet-ApiKey header.
	apiEndpoint       = "https://www.nuget.org/api/v2/package"
	validationTimeout = 10 * time.Second
)

// NewValidator creates a new Validator that validates NuGet.org API keys.
// It calls PUT /api/v2/package with header "X-NuGet-ApiKey: <key>".
// - 400 Bad Request -> authenticated and valid (package file is invalid/missing).
// - 403 Forbidden   -> invalid API key (authentication failure).
// - other           -> validation failed (unexpected response).
func NewValidator() *simplevalidate.Validator[NuGetAPIKey] {
	return &simplevalidate.Validator[NuGetAPIKey]{
		Endpoint:   apiEndpoint,
		HTTPMethod: http.MethodPut,
		HTTPHeaders: func(k NuGetAPIKey) map[string]string {
			return map[string]string{
				"X-NuGet-ApiKey":           k.Key,
				"X-NuGet-Protocol-Version": "4.1.0",
				"Content-Type":             "application/octet-stream",
			}
		},
		ValidResponseCodes:   []int{http.StatusBadRequest},
		InvalidResponseCodes: []int{http.StatusForbidden},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
