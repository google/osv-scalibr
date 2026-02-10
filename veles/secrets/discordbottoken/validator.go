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
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const discordAPIURL = "https://discord.com/api/v10/users/@me"

// NewValidator creates a new Validator that validates the DiscordBotToken via
// the /users/@me API endpoint.
func NewValidator() *sv.Validator[DiscordBotToken] {
	return &sv.Validator[DiscordBotToken]{
		Endpoint:   discordAPIURL,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s DiscordBotToken) map[string]string {
			return map[string]string{
				"Authorization": "Bot " + s.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
	}
}
