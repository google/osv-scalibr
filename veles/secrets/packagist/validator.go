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

package packagist

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewAPIKeyValidator creates a new Packagist API Key Validator.
// It performs a GET request to the Packagist /api/packages/ endpoint
// using the API key in the Authorization header with PACKAGIST-TOKEN scheme.
// If the request returns HTTP 200, the key is considered valid.
// If 401 Unauthorized, the key is invalid. Other errors return ValidationFailed.
func NewAPIKeyValidator() *sv.Validator[APIKey] {
	return &sv.Validator[APIKey]{
		Endpoint:   "https://packagist.com/api/packages/",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s APIKey) map[string]string {
			return map[string]string{
				"Authorization": "PACKAGIST-TOKEN " + s.Key,
				"Accept":        "application/json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}

// NewAPISecretValidator creates a new Packagist API Secret Validator.
// This validator only works when the PackagistAPISecret has both Secret and Key fields populated.
// It validates using HMAC-SHA256 authentication.
// If only the Secret is present (Key is empty), validation returns ValidationFailed with an error.
func NewAPISecretValidator() *sv.Validator[APISecret] {
	return &sv.Validator[APISecret]{
		EndpointFunc: func(secret APISecret) (string, error) {
			if secret.Key == "" {
				return "", errors.New("API key not present; cannot validate secret alone")
			}
			return "https://packagist.com/api/packages/", nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(secret APISecret) map[string]string {
			// Generate HMAC-SHA256 signature
			method := "GET"
			host := "packagist.com"
			path := "/api/packages/"
			timestamp := time.Now().Unix()
			cnonce := strconv.FormatInt(time.Now().UnixNano(), 10)

			// Build query parameters for signature
			params := url.Values{}
			params.Set("cnonce", cnonce)
			params.Set("key", secret.Key)
			params.Set("timestamp", strconv.FormatInt(timestamp, 10))

			// Build string to sign
			stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
				method,
				host,
				path,
				params.Encode(),
			)

			// Generate HMAC-SHA256 signature
			h := hmac.New(sha256.New, []byte(secret.Secret))
			h.Write([]byte(stringToSign))
			signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

			// Build authorization header
			authHeader := fmt.Sprintf("PACKAGIST-HMAC-SHA256 Key=%s, Timestamp=%d, Cnonce=%s, Signature=%s",
				secret.Key,
				timestamp,
				cnonce,
				signature,
			)

			return map[string]string{
				"Authorization": authHeader,
				"Accept":        "application/json",
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
	}
}
