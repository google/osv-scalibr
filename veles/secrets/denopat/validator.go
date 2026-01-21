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

package denopat

import (
	"context"
	"net/http"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// UserTokenValidator validates Deno User PATs via the Deno API endpoint.
type UserTokenValidator struct {
	validator *simplevalidate.Validator[DenoUserPAT]
}

// OrgTokenValidator validates Deno Organization PATs via the Deno API endpoint.
type OrgTokenValidator struct {
	validator *simplevalidate.Validator[DenoOrgPAT]
}

// ValidatorOption configures a Validator when creating it via NewUserTokenValidator or NewOrgTokenValidator.
type ValidatorOption func(any)

// WithClient configures the http.Client that the Validator uses.
//
// By default, it uses http.DefaultClient.
func WithClient(c *http.Client) ValidatorOption {
	return func(v any) {
		switch val := v.(type) {
		case *UserTokenValidator:
			val.validator.HTTPC = c
		case *OrgTokenValidator:
			val.validator.HTTPC = c
		}
	}
}

// NewUserTokenValidator creates a new UserTokenValidator with the given ValidatorOptions.
func NewUserTokenValidator(opts ...ValidatorOption) *UserTokenValidator {
	v := &UserTokenValidator{
		validator: &simplevalidate.Validator[DenoUserPAT]{
			Endpoint:   "https://api.deno.com/user",
			HTTPMethod: http.MethodGet,
			HTTPHeaders: func(pat DenoUserPAT) map[string]string {
				return map[string]string{"Authorization": "Bearer " + pat.Pat}
			},
			ValidResponseCodes:   []int{http.StatusOK},
			InvalidResponseCodes: []int{http.StatusUnauthorized},
			HTTPC:                http.DefaultClient,
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// NewOrgTokenValidator creates a new OrgTokenValidator with the given ValidatorOptions.
func NewOrgTokenValidator(opts ...ValidatorOption) *OrgTokenValidator {
	v := &OrgTokenValidator{
		validator: &simplevalidate.Validator[DenoOrgPAT]{
			Endpoint:   "https://api.deno.com/organization",
			HTTPMethod: http.MethodGet,
			HTTPHeaders: func(pat DenoOrgPAT) map[string]string {
				return map[string]string{"Authorization": "Bearer " + pat.Pat}
			},
			ValidResponseCodes:   []int{http.StatusOK},
			InvalidResponseCodes: []int{http.StatusUnauthorized},
			HTTPC:                http.DefaultClient,
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given DenoUserPAT is valid.
//
// It performs a GET request to https://api.deno.com/user.
// If the request returns HTTP 200, the key is considered valid.
// If 401 Unauthorized, the key is invalid. Other errors return ValidationFailed.
func (v *UserTokenValidator) Validate(ctx context.Context, pat DenoUserPAT) (veles.ValidationStatus, error) {
	return v.validator.Validate(ctx, pat)
}

// Validate checks whether the given DenoOrgPAT is valid.
//
// It performs a GET request to https://api.deno.com/organization.
// If the request returns HTTP 200, the key is considered valid.
// If 401 Unauthorized, the key is invalid. Other errors return ValidationFailed.
func (v *OrgTokenValidator) Validate(ctx context.Context, pat DenoOrgPAT) (veles.ValidationStatus, error) {
	return v.validator.Validate(ctx, pat)
}
