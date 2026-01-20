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
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

// UserTokenValidator validates Deno User PATs via the Deno API endpoint.
type UserTokenValidator struct {
	httpC *http.Client
}

// OrgTokenValidator validates Deno Organization PATs via the Deno API endpoint.
type OrgTokenValidator struct {
	httpC *http.Client
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
			val.httpC = c
		case *OrgTokenValidator:
			val.httpC = c
		}
	}
}

// NewUserTokenValidator creates a new UserTokenValidator with the given ValidatorOptions.
func NewUserTokenValidator(opts ...ValidatorOption) *UserTokenValidator {
	v := &UserTokenValidator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// NewOrgTokenValidator creates a new OrgTokenValidator with the given ValidatorOptions.
func NewOrgTokenValidator(opts ...ValidatorOption) *OrgTokenValidator {
	v := &OrgTokenValidator{
		httpC: http.DefaultClient,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.deno.com/user", nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pat.Pat)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status: %d", res.StatusCode)
	}
}

// Validate checks whether the given DenoOrgPAT is valid.
//
// It performs a GET request to https://api.deno.com/organization.
// If the request returns HTTP 200, the key is considered valid.
// If 401 Unauthorized, the key is invalid. Other errors return ValidationFailed.
func (v *OrgTokenValidator) Validate(ctx context.Context, pat DenoOrgPAT) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.deno.com/organization", nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pat.Pat)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status: %d", res.StatusCode)
	}
}
