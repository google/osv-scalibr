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

package salesforceoauth2access

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	// maxTokenLength is the maximum length of a valid Salesforce OAuth2 Access Token.
	maxTokenLength = 150
)

var (
	// tokenRe is a regular expression that matches salesforce OAuth2 Access Tokens.
	// Here's an official example:
	// Reference: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_refresh_token_flow.htm&type=5
	// Moreover, here are few real word demonstration on youtube:
	// https://youtu.be/WMoyIh0y2Vg?si=3E4cseMwNQvpg0VB&t=440
	// https://youtu.be/kNavqT_7310?si=5w6s8QQijkxhrIGB&t=289
	tokenRe = regexp.MustCompile(`\b00D[0-9A-Za-z]{8,15}![A-Za-z0-9._\-]{30,100}\b`)
)

// NewDetector returns a detector that matches Salesforce OAuth2 client credentials.
func NewDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: maxTokenLength,
		MaxDistance:   1000,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(tokenRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return Token{Token: string(ms[0].Value)}, true
		},
	}
}
