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

// Package sendgrid provides a detector and validator for SendGrid API keys.
package sendgrid

import (
	"io"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	httpClientTimeout   = 10 * time.Second
	sendGridAPIEndpoint = "https://api.sendgrid.com/v3/user/account"
)

func alwaysFailedStatus(body io.Reader) (veles.ValidationStatus, error) {
	return veles.ValidationFailed, nil
}

// NewValidator creates a validator for SendGrid API keys.
// It calls GET /v3/user/account with Bearer auth.
// 200 OK -> valid key
// 403 Forbidden -> valid key (restricted scopes, but key exists and is active)
// 401 Unauthorized -> invalid key
func NewValidator() *simplevalidate.Validator[APIKey] {
	return &simplevalidate.Validator[APIKey]{
		Endpoint:   sendGridAPIEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k APIKey) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k.Key,
				"Content-Type":  "application/json",
			}
		},
		ValidResponseCodes:     []int{http.StatusOK, http.StatusForbidden},
		InvalidResponseCodes:   []int{http.StatusUnauthorized},
		StatusFromResponseBody: alwaysFailedStatus,
		HTTPC:                  &http.Client{Timeout: httpClientTimeout},
	}
}
