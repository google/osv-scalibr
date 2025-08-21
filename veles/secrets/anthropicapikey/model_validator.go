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

package anthropicapikey

import (
	"context"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

var _ veles.Validator[ModelAPIKey] = &ModelValidator{}

// ModelValidator is a Veles Validator for Anthropic Model API keys.
// It validates model API keys by making a test request to the Anthropic API.
type ModelValidator struct {
	config *ValidationConfig
}

// ModelValidatorOption configures a ModelValidator when creating it via NewModelValidator.
type ModelValidatorOption func(*ModelValidator)

// WithModelHTTPClient configures the http.Client that the ModelValidator uses.
//
// By default it uses http.DefaultClient with a timeout.
func WithModelHTTPClient(c *http.Client) ModelValidatorOption {
	return func(v *ModelValidator) {
		v.config.WithHTTPClient(c)
	}
}

// WithModelAPIURL configures the Anthropic API URL that the ModelValidator uses.
//
// By default it uses the production Anthropic API URL.
// This is useful for testing with mock servers.
func WithModelAPIURL(url string) ModelValidatorOption {
	return func(v *ModelValidator) {
		v.config.WithAPIURL(url)
	}
}

// NewModelValidator creates a new ModelValidator with the given ModelValidatorOptions.
func NewModelValidator(opts ...ModelValidatorOption) *ModelValidator {
	v := &ModelValidator{
		config: NewValidationConfig(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given ModelAPIKey is valid.
//
// It makes a request to the /v1/models endpoint which is specific to model keys.
// This endpoint doesn't consume tokens and is used for validation purposes.
func (v *ModelValidator) Validate(ctx context.Context, key ModelAPIKey) (veles.ValidationStatus, error) {
	return validateAPIKey(ctx, v.config, key.Key, "/v1/models")
}
