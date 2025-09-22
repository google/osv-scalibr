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

// PATValidator validates Github app personal access token via the Github API endpoint.
type PATValidator struct {
	httpC *http.Client
}

// PATValidatorOption configures a Validator when creating it via NewValidator.
type PATValidatorOption func(*PATValidator)

// PATWithClient configures the http.Client that the Validator uses.
//
// By default, it uses http.DefaultClient.
func PATWithClient(c *http.Client) PATValidatorOption {
	return func(v *PATValidator) {
		v.httpC = c
	}
}

// NewPATValidator creates a new Validator with the given ValidatorOptions.
func NewPATValidator(opts ...PATValidatorOption) *PATValidator {
	v := &PATValidator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given Github personal access token is valid.
func (v *PATValidator) Validate(ctx context.Context, key PersonalAccessToken) (veles.ValidationStatus, error) {
	return validate.Validate(ctx, v.httpC, "/user", key.Token)
}
