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

package clojarsdeploytoken

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// Validator is a validator for Clojars Deploy Tokens.
type Validator struct {
	HTTPC    *http.Client
	Endpoint string
}

// Validate checks if a Clojars Deploy Token is active.
// It attempts a PUT request to a protected namespace.
// HTTP 403 (Forbidden) indicates the token is valid but unauthorized for that specific path.
// HTTP 401 (Unauthorized) indicates the token/username pair is invalid.
func (v *Validator) Validate(ctx context.Context, k ClojarsDeployToken) (veles.ValidationStatus, error) {
	if k.Username == "" {
		return veles.ValidationInvalid, errors.New("username is empty")
	}

	sv := &simplevalidate.Validator[ClojarsDeployToken]{
		Endpoint:   v.Endpoint,
		HTTPMethod: http.MethodPut,
		Body: func(k ClojarsDeployToken) (string, error) {
			return "test", nil
		},
		HTTPHeaders: func(k ClojarsDeployToken) map[string]string {
			// Clojars uses Basic Auth: base64(username:token)
			auth := k.Username + ":" + k.Token
			return map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(auth)),
				"Content-Type":  "text/plain",
			}
		},
		// 403 is "Valid" because Clojars recognized the user but blocked the specific write.
		ValidResponseCodes:   []int{http.StatusForbidden},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC:                v.HTTPC,
	}

	return sv.Validate(ctx, k)
}

// NewValidator creates a new Validator for Clojars Deploy Tokens.
func NewValidator() *Validator {
	return &Validator{
		// Attempting to write to a core namespace ensures a 403 on valid auth.
		Endpoint: "https://repo.clojars.org/clojure/clojure/9.9.9/dummy.pom",
		HTTPC: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}
