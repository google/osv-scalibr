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

package hcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

// Defaults derived from public HCP API docs.
const (
	defaultTokenURL = "https://auth.idp.hashicorp.com/oauth2/token"
	// Use the Cloud API host for identity introspection.
	defaultAPIBase = "https://api.cloud.hashicorp.com"
)

// ClientCredentialsValidator validates an HCP client credential pair by attempting to exchange it for an access token.
type ClientCredentialsValidator struct {
	httpC    *http.Client
	tokenURL string
}

var _ veles.Validator[ClientCredentials] = &ClientCredentialsValidator{}

// ClientCredentialsValidatorOption configures a ClientCredentialsValidator.
type ClientCredentialsValidatorOption func(*ClientCredentialsValidator)

// WithHTTPClient sets the HTTP client to use.
func WithHTTPClient(c *http.Client) ClientCredentialsValidatorOption {
	return func(v *ClientCredentialsValidator) { v.httpC = c }
}

// WithTokenURL overrides the token endpoint URL.
func WithTokenURL(u string) ClientCredentialsValidatorOption {
	return func(v *ClientCredentialsValidator) { v.tokenURL = u }
}

// NewClientCredentialsValidator creates a new validator with optional configuration.
func NewClientCredentialsValidator(opts ...ClientCredentialsValidatorOption) *ClientCredentialsValidator {
	v := &ClientCredentialsValidator{httpC: http.DefaultClient, tokenURL: defaultTokenURL}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate validates ClientCredentials by attempting a client_credentials OAuth2
// token exchange against the configured token endpoint. A 200 response indicates
// valid credentials; 400/401 indicates invalid; other responses are treated as
// validation failures.
func (v *ClientCredentialsValidator) Validate(ctx context.Context, cc ClientCredentials) (veles.ValidationStatus, error) {
	// If one of the fields is missing, we cannot validate
	if cc.ClientID == "" || cc.ClientSecret == "" {
		return veles.ValidationUnsupported, nil
	}
	if err := ctx.Err(); err != nil {
		return veles.ValidationFailed, err
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cc.ClientID)
	form.Set("client_secret", cc.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to POST %q: %w", v.tokenURL, err)
	}
	defer res.Body.Close()

	// 200 means exchange succeeded: valid credentials.
	if res.StatusCode == http.StatusOK {
		return veles.ValidationValid, nil
	}
	// 400/401 indicates invalid credentials for client credentials flow.
	if res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusUnauthorized {
		// Drain body for completeness.
		_, _ = io.Copy(io.Discard, res.Body)
		return veles.ValidationInvalid, nil
	}
	return veles.ValidationFailed, fmt.Errorf("token endpoint %q returned %q", v.tokenURL, res.Status)
}

// AccessTokenValidator validates an HCP access token by calling the caller-identity endpoint.
type AccessTokenValidator struct {
	httpC   *http.Client
	apiBase string
}

var _ veles.Validator[AccessToken] = &AccessTokenValidator{}

// AccessTokenValidatorOption configures an AccessTokenValidator.
type AccessTokenValidatorOption func(*AccessTokenValidator)

// WithAccessHTTPClient sets the HTTP client for the access token validator.
func WithAccessHTTPClient(c *http.Client) AccessTokenValidatorOption {
	return func(v *AccessTokenValidator) { v.httpC = c }
}

// WithAPIBase overrides the base API URL (default: https://api.cloud.hashicorp.com).
func WithAPIBase(base string) AccessTokenValidatorOption {
	return func(v *AccessTokenValidator) { v.apiBase = strings.TrimRight(base, "/") }
}

// NewAccessTokenValidator creates a new validator for HCP access tokens.
func NewAccessTokenValidator(opts ...AccessTokenValidatorOption) *AccessTokenValidator {
	v := &AccessTokenValidator{httpC: http.DefaultClient, apiBase: defaultAPIBase}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate validates an AccessToken by sending a GET request to the HCP
// caller-identity endpoint with the token as a Bearer credential.
//
// Documentation: https://developer.hashicorp.com/hcp/api-docs/identity#IamService_GetCallerIdentity
//
// - 200: token is valid (identity returned)
// - 401: token is invalid
// - any other response: treated as ValidationFailed
func (v *AccessTokenValidator) Validate(ctx context.Context, at AccessToken) (veles.ValidationStatus, error) {
	if err := ctx.Err(); err != nil {
		return veles.ValidationFailed, err
	}
	endpoint := v.apiBase + "/iam/2019-12-10/caller-identity"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+at.Token)
	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", endpoint, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("GET %q returned %q", endpoint, res.Status)
	}
}
