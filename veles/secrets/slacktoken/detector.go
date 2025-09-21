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

// Package slacktoken contains a Veles Secret type and a Detector for
// Slack App Tokens including App Level Tokens (prefix `xapp-`),
// App Configuration Access Tokens (prefix `xoxe.xoxp-`), and
// App Configuration Refresh Tokens (prefix `xoxe-`).
package slacktoken

import (
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// maxTokenLength is the maximum size of a Slack API token.
const maxTokenLength = 178

// keyRe is a regular expression that matches a Slack App token.
// Slack App Level Tokens have the form: `xapp-` followed by a number,
// a dash, an app ID, a dash, and 64 hex characters.
var appLevelTokenRe = regexp.MustCompile(`xapp-\d+-[A-Za-z0-9]{11}-[0-9]{13}-[a-fA-F0-9]{64}`)

// appConfigAccessTokenRe is a regular expression that matches a Slack App Configuration Access token.
// Slack App Configuration Access token has the form: `xoxe.xoxp-` followed by a number,
// a dash, and 166 alphanumeric characters.
var appConfigAccessTokenRe = regexp.MustCompile(`xoxe\.xoxp-\d+-[a-zA-Z0-9]{166}`)

// appConfigRefreshTokenRe is a regular expression that matches a Slack App Configuration Refresh token.
// Slack App Configuration Refresh token has the form: `xoxe-` followed by a number,
// a dash, and 147 alphanumeric characters.
var appConfigRefreshTokenRe = regexp.MustCompile(`xoxe-\d+-[a-zA-Z0-9]{147}`)

var _ veles.Detector = NewDetector()

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a new Detector that matches
// Slack App tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxTokenLength
}

func (d *detector) Detect(content []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var offsets []int

	// Detect App Level Tokens (xapp-...)
	appLevelMatches := appLevelTokenRe.FindAllSubmatch(content, -1)
	for _, m := range appLevelMatches {
		if len(m[0]) > 0 {
			token := string(m[0])
			secrets = append(secrets, SlackToken{
				Token:                   token,
				IsAppLevelToken:         true,
				IsAppConfigAccessToken:  false,
				IsAppConfigRefreshToken: false,
			})
			offsets = append(offsets, bytes.Index(content, m[0]))
		}
	}

	// Detect App Configuration Access Tokens (xoxe.xoxp-...)
	configAccessMatches := appConfigAccessTokenRe.FindAllSubmatch(content, -1)
	for _, m := range configAccessMatches {
		if len(m[0]) > 0 {
			token := string(m[0])
			secrets = append(secrets, SlackToken{
				Token:                   token,
				IsAppLevelToken:         false,
				IsAppConfigAccessToken:  true,
				IsAppConfigRefreshToken: false,
			})
			offsets = append(offsets, bytes.Index(content, m[0]))
		}
	}

	// Detect App Configuration Refresh Tokens (xoxe-...)
	configRefreshMatches := appConfigRefreshTokenRe.FindAllSubmatch(content, -1)
	for _, m := range configRefreshMatches {
		if len(m[0]) > 0 {
			token := string(m[0])
			secrets = append(secrets, SlackToken{
				Token:                   token,
				IsAppLevelToken:         false,
				IsAppConfigAccessToken:  false,
				IsAppConfigRefreshToken: true,
			})
			offsets = append(offsets, bytes.Index(content, m[0]))
		}
	}

	return secrets, offsets
}
