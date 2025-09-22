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

// AppU2STokenValidator validates Github app User to Server token via the Github API endpoint.
type AppU2STokenValidator struct {
	httpC *http.Client
}

// AppU2STokenValidatorOption configures a AppU2SValidator when creating it via NewAppU2SValidator.
type AppU2STokenValidatorOption func(*AppU2STokenValidator)

// AppU2STokenWithClient configures the http.Client that the AppU2SValidator uses.
//
// By default, it uses http.DefaultClient.
func AppU2STokenWithClient(c *http.Client) AppU2STokenValidatorOption {
	return func(v *AppU2STokenValidator) {
		v.httpC = c
	}
}

// NewAppU2STokenValidator creates a new AppU2SValidator with the given AppU2SValidatorOptions.
func NewAppU2STokenValidator(opts ...AppU2STokenValidatorOption) *AppU2STokenValidator {
	v := &AppU2STokenValidator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given Github app User to Server token is valid.
func (v *AppU2STokenValidator) Validate(ctx context.Context, key AppUserToServerToken) (veles.ValidationStatus, error) {
	return validate.Validate(ctx, v.httpC, "/user", key.Token)
}
