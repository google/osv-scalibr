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

package slacktoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

// slackResponse represents the common response structure from Slack API
type slackResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

//
// --- Slack App Level Token Validator ---
//

var _ veles.Validator[SlackAppLevelToken] = &ValidatorAppLevelToken{}

// ValidatorAppLevelToken validates Slack App Level Tokens via the Slack API.
type ValidatorAppLevelToken struct {
	httpC *http.Client
}

// ValidatorOptionAppLevelToken configures a ValidatorAppLevelToken when creating it.
type ValidatorOptionAppLevelToken func(*ValidatorAppLevelToken)

// WithClientAppLevelToken configures the http.Client that the ValidatorAppLevelToken uses.
//
// By default, it uses http.DefaultClient.
func WithClientAppLevelToken(c *http.Client) ValidatorOptionAppLevelToken {
	return func(v *ValidatorAppLevelToken) {
		v.httpC = c
	}
}

// NewAppLevelTokenValidator creates a new ValidatorAppLevelToken with the given options.
func NewAppLevelTokenValidator(opts ...ValidatorOptionAppLevelToken) *ValidatorAppLevelToken {
	v := &ValidatorAppLevelToken{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given SlackAppLevelToken is valid.
// It sends a request to the Slack API endpoint `auth.test` to verify the token.
func (v *ValidatorAppLevelToken) Validate(ctx context.Context, key SlackAppLevelToken) (veles.ValidationStatus, error) {
	return validateSlackToken(ctx, v.httpC, key.Token)
}

//
// --- Slack App Configuration Access Token Validator ---
//

var _ veles.Validator[SlackAppConfigAccessToken] = &ValidatorAppConfigAccessToken{}

// ValidatorAppConfigAccessToken validates Slack App Config Access Tokens via the Slack API.
type ValidatorAppConfigAccessToken struct {
	httpC *http.Client
}

// ValidatorOptionAppConfigAccessToken configures a ValidatorAppConfigAccessToken when creating it.
type ValidatorOptionAppConfigAccessToken func(*ValidatorAppConfigAccessToken)

// WithClientAppConfigAccessToken configures the http.Client that the ValidatorAppConfigAccessToken uses.
//
// By default, it uses http.DefaultClient.
func WithClientAppConfigAccessToken(c *http.Client) ValidatorOptionAppConfigAccessToken {
	return func(v *ValidatorAppConfigAccessToken) {
		v.httpC = c
	}
}

// NewAppConfigAccessTokenValidator creates a new ValidatorAppConfigAccessToken with the given options.
func NewAppConfigAccessTokenValidator(opts ...ValidatorOptionAppConfigAccessToken) *ValidatorAppConfigAccessToken {
	v := &ValidatorAppConfigAccessToken{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given SlackAppConfigAccessToken is valid.
// It sends a request to the Slack API endpoint `auth.test` to verify the token.
func (v *ValidatorAppConfigAccessToken) Validate(ctx context.Context, key SlackAppConfigAccessToken) (veles.ValidationStatus, error) {
	return validateSlackToken(ctx, v.httpC, key.Token)
}

//
// --- Slack App Configuration Refresh Token Validator ---
//

var _ veles.Validator[SlackAppConfigRefreshToken] = &ValidatorAppConfigRefreshToken{}

// ValidatorAppConfigRefreshToken validates Slack App Config Refresh Tokens via the Slack API.
type ValidatorAppConfigRefreshToken struct {
	httpC *http.Client
}

// ValidatorOptionAppConfigRefreshToken configures a ValidatorAppConfigRefreshToken when creating it.
type ValidatorOptionAppConfigRefreshToken func(*ValidatorAppConfigRefreshToken)

// WithClientAppConfigRefreshToken configures the http.Client that the ValidatorAppConfigRefreshToken uses.
//
// By default, it uses http.DefaultClient.
func WithClientAppConfigRefreshToken(c *http.Client) ValidatorOptionAppConfigRefreshToken {
	return func(v *ValidatorAppConfigRefreshToken) {
		v.httpC = c
	}
}

// NewAppConfigRefreshTokenValidator creates a new ValidatorAppConfigRefreshToken with the given options.
func NewAppConfigRefreshTokenValidator(opts ...ValidatorOptionAppConfigRefreshToken) *ValidatorAppConfigRefreshToken {
	v := &ValidatorAppConfigRefreshToken{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given SlackAppConfigRefreshToken is valid.
// It sends a request to the Slack API endpoint `auth.test` to verify the token.
func (v *ValidatorAppConfigRefreshToken) Validate(ctx context.Context, key SlackAppConfigRefreshToken) (veles.ValidationStatus, error) {
	return validateSlackToken(ctx, v.httpC, key.Token)
}

// validateSlackToken is a helper function that validates a Slack token by sending a request
// to the Slack API endpoint. This is common code used by all three validators.
func validateSlackToken(ctx context.Context, httpC *http.Client, token string) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/auth.test", nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}

	var response slackResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if response.Ok {
		return veles.ValidationValid, nil
	} else if response.Error == "invalid_auth" {
		return veles.ValidationInvalid, nil
	}
	return veles.ValidationFailed, nil
}
