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
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// Validator is a validator for DockerHub PATs.
type Validator struct {
	HTTPC    *http.Client
	Endpoint string
}

// Validate validates a DockerHub PAT.
//
// It performs a POST request to the Docker Hub create access token endpoint
// using the PAT and username in the request body. If the request returns
// HTTP 200, the key is considered valid. If 401 Unauthorized or PAT's Username
// is empty, the key is invalid. Other errors return ValidationFailed.
func (v *Validator) Validate(ctx context.Context, k DockerHubPAT) (veles.ValidationStatus, error) {
	if k.Username == "" {
		return veles.ValidationInvalid, errors.New("username is empty")
	}
	// We use a wrapper around simplevalidate to provide more accurate validation
	// of the secrets. Otherwise, we wouldn't be able to fit this extra logic into
	// the simplevalidate model.
	sv := &simplevalidate.Validator[DockerHubPAT]{
		Endpoint:   v.Endpoint,
		HTTPMethod: http.MethodPost,
		Body: func(k DockerHubPAT) (string, error) {
			return fmt.Sprintf(`{"identifier": "%s","secret": "%s"}`, k.Username, k.Pat), nil
		},
		HTTPHeaders: func(k DockerHubPAT) map[string]string {
			return map[string]string{
				"Content-Type": "application/json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC:                v.HTTPC,
	}
	return sv.Validate(ctx, k)
}

// NewValidator creates a new Validator for DockerHub PATs.
func NewValidator() *Validator {
	return &Validator{
		Endpoint: "https://hub.docker.com/v2/auth/token/",
		HTTPC: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}
