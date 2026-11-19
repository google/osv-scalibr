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

package paypal

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// httpClientTimeout bounds each validation request.
	httpClientTimeout = 10 * time.Second
	// paypalLiveTokenEndpoint is the PayPal OAuth2 token endpoint for Live
	// credentials.
	paypalLiveTokenEndpoint = "https://api-m.paypal.com/v1/oauth2/token"
	// paypalSandboxTokenEndpoint is the PayPal OAuth2 token endpoint for
	// Sandbox credentials.
	paypalSandboxTokenEndpoint = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
)

// NewValidator creates a new PayPal credential Validator.
//
// It validates PayPal REST API credentials by attempting the OAuth2
// client_credentials grant against the PayPal token endpoints. A credential
// pair is scoped to exactly one environment, so the Live and Sandbox endpoints
// are queried in order: a 200 from either means the credentials are valid; a
// 401 from both means they are invalid; anything else (5xx, network, timeout)
// is reported as ValidationFailed.
func NewValidator() *simplevalidate.Validator[Credentials] {
	return &simplevalidate.Validator[Credentials]{
		Endpoints:  []string{paypalLiveTokenEndpoint, paypalSandboxTokenEndpoint},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(c Credentials) map[string]string {
			return map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(c.ID+":"+c.Secret)),
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		Body: func(c Credentials) (string, error) {
			return "grant_type=client_credentials", nil
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
		HTTPC:                &http.Client{Timeout: httpClientTimeout},
	}
}
