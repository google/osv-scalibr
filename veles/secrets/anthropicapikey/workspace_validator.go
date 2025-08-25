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

var _ veles.Validator[WorkspaceAPIKey] = &WorkspaceValidator{}

// WorkspaceValidator is a Veles Validator for Anthropic Workspace API keys.
// It validates workspace API keys by making a test request to the Anthropic API.
type WorkspaceValidator struct {
	config *ValidationConfig
}

// WorkspaceValidatorOption configures a WorkspaceValidator when creating it via NewWorkspaceValidator.
type WorkspaceValidatorOption func(*WorkspaceValidator)

// WithWorkspaceHTTPClient configures the http.Client that the WorkspaceValidator uses.
//
// By default it uses http.DefaultClient with a timeout.
func WithWorkspaceHTTPClient(c *http.Client) WorkspaceValidatorOption {
	return func(v *WorkspaceValidator) {
		v.config.WithHTTPClient(c)
	}
}

// WithWorkspaceAPIURL configures the Anthropic API URL that the WorkspaceValidator uses.
//
// By default it uses the production Anthropic API URL.
// This is useful for testing with mock servers.
func WithWorkspaceAPIURL(url string) WorkspaceValidatorOption {
	return func(v *WorkspaceValidator) {
		v.config.WithAPIURL(url)
	}
}

// NewWorkspaceValidator creates a new WorkspaceValidator with the given WorkspaceValidatorOptions.
func NewWorkspaceValidator(opts ...WorkspaceValidatorOption) *WorkspaceValidator {
	v := &WorkspaceValidator{
		config: NewValidationConfig(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given WorkspaceAPIKey is valid.
//
// It makes a request to the /v1/organizations/workspaces endpoint which is specific to workspace keys.
// This endpoint doesn't consume tokens and is used for validation purposes.
func (v *WorkspaceValidator) Validate(ctx context.Context, key WorkspaceAPIKey) (veles.ValidationStatus, error) {
	return validateAPIKey(ctx, v.config, key.Key, "/v1/organizations/workspaces")
}
