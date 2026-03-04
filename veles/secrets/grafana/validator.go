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

package grafana

import (
	"errors"
	"fmt"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewServiceAccountTokenValidator creates a Validator for Grafana Service Account Tokens.
func NewServiceAccountTokenValidator() *sv.Validator[ServiceAccountToken] {
	return &sv.Validator[ServiceAccountToken]{
		EndpointFunc: func(token ServiceAccountToken) (string, error) {
			if token.Stack == "" {
				return "", errors.New("stack not present; cannot validate token alone")
			}
			return fmt.Sprintf("https://%s/api/user/", token.Stack), nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s ServiceAccountToken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + s.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}

// NewCloudTokenValidator creates a Validator for Grafana Cloud Tokens.
func NewCloudTokenValidator() *sv.Validator[CloudToken] {
	return &sv.Validator[CloudToken]{
		Endpoint:   "https://grafana.com/api/instances",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s CloudToken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + s.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
