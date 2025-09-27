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
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewAppLevelTokenDetector()
	_ veles.Detector = NewAppConfigAccessTokenDetector()
	_ veles.Detector = NewAppConfigRefreshTokenDetector()
)

// App Level Token: prefix `xapp-` followed by digits (presumably with max 10 digits), a dash, an app ID,
// a dash, and 64 hex characters.
const appLevelTokenMaxLen = 106

var appLevelTokenRe = regexp.MustCompile(`xapp-\d{1,10}-[A-Za-z0-9]{11}-[0-9]{13}-[a-fA-F0-9]{64}`)

// App Configuration Access Token: prefix `xoxe.xoxp-` followed by digits (presumably with max 10 digits),
// a dash, and 166 alphanumeric characters.
const appConfigAccessTokenMaxLen = 187

var appConfigAccessTokenRe = regexp.MustCompile(`xoxe\.xoxp-\d{1,10}-[a-zA-Z0-9]{166}`)

// App Configuration Refresh Token: prefix `xoxe-` followed by digits (presumably with max 10 digits),
// a dash, and 147 alphanumeric characters.
const appConfigRefreshTokenMaxLen = 163

var appConfigRefreshTokenRe = regexp.MustCompile(`xoxe-\d{1,10}-[a-zA-Z0-9]{147}`)

// NewAppLevelTokenDetector returns a detector for Slack App Level Tokens (xapp-...).
func NewAppLevelTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: appLevelTokenMaxLen,
		Re:     appLevelTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return SlackAppLevelToken{Token: string(b)}, true
		},
	}
}

// NewAppConfigAccessTokenDetector returns a detector for Slack App Configuration Access Tokens (xoxe.xoxp-...).
func NewAppConfigAccessTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: appConfigAccessTokenMaxLen,
		Re:     appConfigAccessTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return SlackAppConfigAccessToken{Token: string(b)}, true
		},
	}
}

// NewAppConfigRefreshTokenDetector returns a detector for Slack App Configuration Refresh Tokens (xoxe-...).
func NewAppConfigRefreshTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: appConfigRefreshTokenMaxLen,
		Re:     appConfigRefreshTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return SlackAppConfigRefreshToken{Token: string(b)}, true
		},
	}
}
