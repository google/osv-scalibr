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
	"errors"
	"fmt"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// telegramBotAPIBaseURL is the base URL for Slack API.
	telegramBotAPIBaseURL = "https://api.telegram.org"
	// telegramBotAPIEndpoint is the API endpoint for token validation.
	telegramBotAPIEndpoint = "/bot%s/getMe"
)

// NewValidator creates a new Validator that validates the TelegramBotAPIToken via
// the getMe API endpoint.
//
// It performs a POST request to the Telegram Bot API endpoint to test bot's auth token.
// It requires no parameters. Returns basic information about the bot in form of a User object.
// Valid tokens return 200 Success, while invalid tokens return 401 Unauthorized.
func NewValidator() *sv.Validator[TelegramBotAPIToken] {
	return &sv.Validator[TelegramBotAPIToken]{
		EndpointFunc: func(t TelegramBotAPIToken) (string, error) {
			if t.Token == "" {
				return "", errors.New("telegram bot token is empty")
			}
			return telegramBotAPIBaseURL + fmt.Sprintf(telegramBotAPIEndpoint, t.Token), nil
		},
		HTTPMethod:           http.MethodPost,
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
