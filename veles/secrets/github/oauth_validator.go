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
	"net/http"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/github/validate"
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
	return validate.Validate(ctx, v.httpC, "/user", key.Token)
}
