// Copyright 2026 Google LLC
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

package telegrambotapitoken

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

const (
	// telegramBotAPIBaseURL is the base URL for Slack API.
	telegramBotAPIBaseURL = "https://api.telegram.org"
	// telegramBotAPIEndpoint is the API endpoint for token validation.
	telegramBotAPIEndpoint = "/bot%s/getMe"
)

// SecretTokenValidator validates Telegram Bot API Tokens using /bot{token}/getMe endpoint.
type SecretTokenValidator struct {
	httpC *http.Client
}

// ValidatorOptionSecretToken configures a SecretTokenValidator when creating it via New.
type ValidatorOptionSecretToken func(*SecretTokenValidator)

// WithClientSecretToken configures the http.Client used by SecretTokenValidator.
//
// By default it uses http.DefaultClient.
func WithClientSecretToken(c *http.Client) ValidatorOptionSecretToken {
	return func(v *SecretTokenValidator) {
		v.httpC = c
	}
}

// NewSecretTokenValidator creates a new SecretTokenValidator with the given options.
func NewSecretTokenValidator(opts ...ValidatorOptionSecretToken) *SecretTokenValidator {
	v := &SecretTokenValidator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate creates a new Validator that validates the TelegramBotAPIToken via
// the getMe API endpoint.
//
// It performs a POST request to the Telegram Bot API endpoint to test bot's auth token.
// It requires no parameters. Returns basic information about the bot in form of a User object.
// Valid tokens return 200 Success, while invalid tokens return 401 Unauthorized.
func (v *SecretTokenValidator) Validate(ctx context.Context, token TelegramBotAPIToken) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, telegramBotAPIBaseURL+fmt.Sprintf(telegramBotAPIEndpoint, token.Token), nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to POST %q: %w", telegramBotAPIEndpoint, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// 200 OK => the token is valid and authenticated.
		return veles.ValidationValid, nil
	default:
		// Any other status code => invalid token.
		return veles.ValidationInvalid, nil
	}
}
