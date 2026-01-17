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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stripeapikeys

import (
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	httpClientTimeout = 10 * time.Second
	stripeAPIEndpoint = "https://api.stripe.com/v1/accounts"
)

func authHeader(key string) map[string]string {
	return map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(key+":")),
	}
}

func alwaysInvalidStatus(body io.Reader) (veles.ValidationStatus, error) {
	return veles.ValidationInvalid, nil
}

// NewSecretKeyValidator validates Stripe Secret Keys (sk_live_...) using /v1/accounts.
//
// It calls GET https://api.stripe.com/v1/accounts with Basic Auth. If the response
// is 200 OK, the key is considered valid. Otherwise, it is considered invalid.
func NewSecretKeyValidator() *simplevalidate.Validator[StripeSecretKey] {
	return &simplevalidate.Validator[StripeSecretKey]{
		Endpoint:   stripeAPIEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k StripeSecretKey) map[string]string {
			return authHeader(k.Key)
		},
		ValidResponseCodes:     []int{http.StatusOK},
		StatusFromResponseBody: alwaysInvalidStatus,
		HTTPC:                  &http.Client{Timeout: httpClientTimeout},
	}
}

// NewRestrictedKeyValidator creates a validator for Stripe Restricted Keys.
//
// It calls GET https://api.stripe.com/v1/accounts with Basic Auth.
// Restricted Keys are scoped to specific endpoints and permissions, so a 403
// from /v1/accounts does not necessarily mean the key is invalid.
// Possible outcomes:
//   - 200 OK       -> key has access to this endpoint and is valid.
//   - 403 Forbidden -> key is valid but lacks permission for this endpoint;
//     it may still work for other allowed endpoints.
//   - other         -> key is invalid.
func NewRestrictedKeyValidator() *simplevalidate.Validator[StripeRestrictedKey] {
	return &simplevalidate.Validator[StripeRestrictedKey]{
		Endpoint:   stripeAPIEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k StripeRestrictedKey) map[string]string {
			return authHeader(k.Key)
		},
		ValidResponseCodes:     []int{http.StatusOK, http.StatusForbidden},
		StatusFromResponseBody: alwaysInvalidStatus,
		HTTPC:                  &http.Client{Timeout: httpClientTimeout},
	}
}
