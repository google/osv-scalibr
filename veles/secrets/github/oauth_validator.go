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

package github

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

// OAuthTokenValidator validates Github OAuth token via the Github API endpoint.
type OAuthTokenValidator struct {
	httpC *http.Client
}

// OAuthTokenValidatorOption configures a OAuthValidator when creating it via NewOAuthValidator.
type OAuthTokenValidatorOption func(*OAuthTokenValidator)

// OAuthTokenWithClient configures the http.Client that the OAuthValidator uses.
//
// By default, it uses http.DefaultClient.
func OAuthTokenWithClient(c *http.Client) OAuthTokenValidatorOption {
	return func(v *OAuthTokenValidator) {
		v.httpC = c
	}
}

// NewOAuthTokenValidator creates a new OAuthValidator with the given OAuthValidatorOptions.
func NewOAuthTokenValidator(opts ...OAuthTokenValidatorOption) *OAuthTokenValidator {
	v := &OAuthTokenValidator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given Github OAuth token is valid.
func (v *OAuthTokenValidator) Validate(ctx context.Context, key OAuthToken) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/user", nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	//nolint:canonicalheader // This header is set as "X-GitHub-Api-Version" exactly as documented by GitHub.
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer res.Body.Close()
	_, err = io.ReadAll(res.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}

	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, nil
	}
}
