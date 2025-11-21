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

package dockerhubpat

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewValidator creates a new Validator for DockerHub PATs.
//
// It performs a POST request to the Docker Hub create access token endpoint
// using the PAT and username in the request body. If the request returns
// HTTP 200, the key is considered valid. If 401 Unauthorized, the key
// is invalid. Other errors return ValidationFailed.
func NewValidator() *simplevalidate.Validator[DockerHubPAT] {
	return &simplevalidate.Validator[DockerHubPAT]{
		Endpoint:   "https://hub.docker.com/v2/auth/token/",
		HTTPMethod: http.MethodPost,
		Body: func(k DockerHubPAT) (string, error) {
			if k.Username == "" {
				return "", errors.New("username is empty")
			}
			return fmt.Sprintf(`{"identifier": "%s","secret": "%s"}`, k.Username, k.Pat), nil
		},
		HTTPHeaders: func(k DockerHubPAT) map[string]string {
			return map[string]string{
				"Content-Type": "application/json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}
