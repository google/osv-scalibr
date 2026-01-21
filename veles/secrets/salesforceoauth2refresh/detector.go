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

package salesforceoauth2refresh

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	// maxIDLength is the maximum length of a valid client ID.
	maxIDLength = 184

	// maxSecretLength is the maximum length of a valid client secret.
	// There is not documented length but 100 is a good upper bound.
	maxSecretLength = 100

	// maxDistance is the maximum distance between client IDs and secrets to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	// clientIDRe is a regular expression that matches salesforce OAuth2 client IDs.
	// Here's an official example:
	// Reference: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_refresh_token_flow.htm&type=5
	// Moreover, here are few real word demonstration on youtube:
	// https://youtu.be/WMoyIh0y2Vg?si=3E4cseMwNQvpg0VB&t=440
	// https://youtu.be/kNavqT_7310?si=5w6s8QQijkxhrIGB&t=289

	clientIDRe = regexp.MustCompile(`\b3MVG[a-zA-Z0-9._\-]{20,180}\b`)

	// clientSecretRe is a regular expression that matches salesforce OAuth2 client secrets.
	// There is no clear documentation on the exact format of salesforce OAuth2 client secrets.
	// But official examples suggest it's a random string of integers:
	// Reference: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_refresh_token_flow.htm&type=5
	// Moreover, real word demonstrations on youtube suggest it is Alphanumeric:
	// https://youtu.be/WMoyIh0y2Vg?si=3E4cseMwNQvpg0VB&t=440
	// https://youtu.be/kNavqT_7310?si=5w6s8QQijkxhrIGB&t=289
	clientSecretRe = regexp.MustCompile(`(?i)\bclient_secret\b\s*[:=]\s*([A-Za-z0-9]{30,100})\b`)

	// refreshRe is a regular expression that matches Salesforce OAuth2 refresh tokens.
	refreshRe = regexp.MustCompile(`(?i)\brefresh_token\b\s*[:=]\s*([A-Za-z0-9]{30,100})\b`)
)

// NewDetector returns a detector that matches Salesforce OAuth2 client credentials.
func NewDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxIDLength, maxSecretLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(clientIDRe),
			ntuple.FindAllMatchesGroup(clientSecretRe),
			ntuple.FindAllMatchesGroup(refreshRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return Credentials{ID: string(ms[0].Value), Secret: string(ms[1].Value), Refresh: string(ms[2].Value)}, true
		},
	}
}
