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

package discordbottoken

import (
	"errors"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// discordAPIBaseURL is the base URL for Discord API.
	discordAPIBaseURL = "https://discord.com/api/v10"
	// discordUserEndpoint is the API endpoint for token validation.
	discordUserEndpoint = "/users/@me"
)

// NewValidator creates a new Validator that validates the DiscordBotToken via
// the /users/@me API endpoint.
//
// It performs a GET request to the Discord API endpoint to test bot's auth
// token. Valid tokens return 200 OK, while invalid tokens return 401
// Unauthorized.
//
// Reference: https://discord.com/developers/docs/resources/user#get-current-user
func NewValidator() *sv.Validator[DiscordBotToken] {
	return &sv.Validator[DiscordBotToken]{
		EndpointFunc: func(t DiscordBotToken) (string, error) {
			if t.Token == "" {
				return "", errors.New("discord bot token is empty")
			}
			return discordAPIBaseURL + discordUserEndpoint, nil
		},
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(t DiscordBotToken) map[string]string {
			// Discord Bot tokens require "Bot " prefix in Authorization header
			return map[string]string{
				"Authorization": "Bot " + t.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
