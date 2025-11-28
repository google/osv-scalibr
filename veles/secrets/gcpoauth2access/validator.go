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

package gcpoauth2access

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// endpoint is the URL of Google's OAuth2 tokeninfo endpoint.
	// https://developers.google.com/identity/protocols/oauth2
	endpoint = "https://www.googleapis.com/oauth2/v3/tokeninfo"
)

// NewValidator creates a new Validator for GCP OAuth2 access tokens.
func NewValidator() *simplevalidate.Validator[Token] {
	return &simplevalidate.Validator[Token]{
		EndpointFunc: func(t Token) (string, error) {
			if t.Token == "" {
				return "", errors.New("OAuth2 token is empty")
			}
			return fmt.Sprintf("%s?access_token=%s", endpoint, t.Token), nil
		},
		HTTPMethod:             http.MethodGet,
		InvalidResponseCodes:   []int{http.StatusBadRequest},
		StatusFromResponseBody: statusFromResponseBody,
		HTTPC:                  &http.Client{Timeout: 10 * time.Second},
	}
}

// statusFromResponseBody extracts the validation status from the HTTP response body.
// It checks if the token has any scopes and if it's expired based on
// 'expires_in' or 'exp' fields from the token info.
// The token is considered valid if it contains any scopes and is not expired,
// invalid if it has no scopes or is expired, and validation fails if the
// expiration status cannot be determined.
func statusFromResponseBody(body io.Reader, _ Token, _ *http.Request) (veles.ValidationStatus, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response: %w", err)
	}

	var tokenInfo response
	if err := json.Unmarshal(bodyBytes, &tokenInfo); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse response: %w", err)
	}

	// Token is recognized. Check scopes and expiration.
	if tokenInfo.Scope == "" {
		// Token does not have access to any scopes.
		return veles.ValidationInvalid, nil
	}

	expiresIn, err := strconv.ParseInt(tokenInfo.ExpiresIn, 10, 64)
	if err == nil {
		if expiresIn > 0 {
			return veles.ValidationValid, nil
		}
		return veles.ValidationInvalid, nil
	}

	expiresAt, err := strconv.ParseInt(tokenInfo.Expiry, 10, 64)
	if err == nil && expiresAt > 0 {
		expire := time.Unix(expiresAt, 0)
		if time.Now().Before(expire) {
			return veles.ValidationValid, nil
		}
		return veles.ValidationInvalid, nil
	}

	// If we can't determine expiration, consider validation failed.
	return veles.ValidationFailed, errors.New("failed to determine token expiration")
}

// response represents the response from Google's OAuth2 token endpoint.
// https://developers.google.com/identity/protocols/oauth2
type response struct {
	// Expiry is the expiration time of the token in Unix time.
	Expiry string `json:"exp"`
	// ExpiresIn is the number of seconds until the token expires.
	ExpiresIn string `json:"expires_in"`
	// Scope is a space-delimited list that identify the resources that your application could access
	// https://developers.google.com/identity/protocols/oauth2/scopes
	Scope string `json:"scope"`
}
