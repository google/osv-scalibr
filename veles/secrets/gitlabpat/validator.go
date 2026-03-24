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

package gitlabpat

import (
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	httpClientTimeout = 10 * time.Second
	gitlabAPIEndpoint = "https://gitlab.com/api/v4/personal_access_tokens/self"
)

// NewValidator creates a new Validator for Gitlab PATs via the Gitlab API endpoint.
//
// It performs a GET request to the gitlab.com access token endpoint
// using the PAT in the PRIVATE-TOKEN header. If the request returns
// HTTP 200, the key is considered valid. If 401 Unauthorized, the key
// is invalid. Other errors return ValidationFailed.
func NewValidator() *simplevalidate.Validator[GitlabPAT] {
	return &simplevalidate.Validator[GitlabPAT]{
		Endpoint:   gitlabAPIEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(secret GitlabPAT) map[string]string {
			return map[string]string{
				"PRIVATE-TOKEN": secret.Pat,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC:                &http.Client{Timeout: httpClientTimeout},
	}
}
