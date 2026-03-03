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

package sap

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	maxConcurClientSecretLength = 60
	maxConcurRefreshTokenLength = 60
)

var (
	// concurClientSecretRe is a regular expression that matches SAP Concur OAuth2 Client Secrets.
	// It is a UUID-like string (mentioned in official documentation) which is exactly either 32 or 36 symbols long.
	// Reference:
	// https://developer.concur.com/api-reference/authentication/apidoc.html#refresh_token
	concurClientSecretRe = regexp.MustCompile(`(?i)\bclient[_-]?secret\b\s*[:=]?\s*([a-zA-Z0-9-]{32,36})\b`)

	// concurRefreshTokenRe is a regular expression that matches SAP Concur Refresh Tokens.
	// It is a UUID-like string (mentioned in official documentation) which is exactly either 32 or 36 symbols long.
	//
	// Moreover, in "Managing tokens" section of the official documentation (link given below) it's clearly mentioned:
	//
	// """
	// The exact format of the string can change, but may look similar to the following:
	// e013335d-b4ce-4c43-a7e4-b67abc1adcb0
	// or like this:
	// 2d725xipty0z7ha3vlpy8b2c3hqxmw
	// """
	//
	// Reference:
	// https://developer.concur.com/api-reference/authentication/apidoc.html#refresh_token
	concurRefreshTokenRe = regexp.MustCompile(`(?i)\brefresh[_-]?token\b\s*[:=]?\s*([a-zA-Z0-9-]{32,36})\b`)
)

// NewSAPConcurRefreshTokenDetector returns a detector that matches SAP Concur Refresh Token.
func NewSAPConcurRefreshTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxAribaIDLength, maxConcurClientSecretLength, maxConcurRefreshTokenLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatchesGroup(aribaClientIDRe), // because client id is an UUID-like string just like SAP Ariba
			ntuple.FindAllMatchesGroup(concurClientSecretRe),
			ntuple.FindAllMatchesGroup(concurRefreshTokenRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return ConcurRefreshToken{ID: string(ms[0].Value), Secret: string(ms[1].Value), Token: string(ms[2].Value)}, true
		},
	}
}
