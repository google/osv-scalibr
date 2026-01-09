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

// SlackAppLevelToken is a Veles Secret that holds relevant information for
// Slack tokens including App Level Tokens (prefix `xapp-`).
// SlackAppLevelToken represents tokens used to authenticate requests
type SlackAppLevelToken struct {
	Token string
}

// SlackAppConfigAccessToken is a Veles Secret that holds relevant information for
// App Configuration Access Tokens (prefix `xoxe.xoxp-`).
// SlackAppConfigAccessToken represents tokens used to authenticate requests
type SlackAppConfigAccessToken struct {
	Token string
}

// SlackAppConfigRefreshToken is a Veles Secret that holds relevant information for
// App Configuration Refresh Tokens (prefix `xoxe-`).
// SlackAppConfigRefreshToken represents tokens used to authenticate requests
type SlackAppConfigRefreshToken struct {
	Token string
}
