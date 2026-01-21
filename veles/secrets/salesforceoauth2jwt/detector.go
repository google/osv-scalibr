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

package salesforceoauth2jwt

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	// maxIDLength is the maximum length of a valid client ID.
	// There is not documented length but 200 is a good upper bound.
	maxIDLength = 200

	// maxPrivateKeyLength is the maximum length of a private key block.
	maxPrivateKeyLength = 1280 * 1024

	// maxDistance is the maximum distance between client IDs and private keys to be considered for pairing.
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

	// usernameRe is a regular expression that matches salesforce Username emails.
	usernameRe = regexp.MustCompile(`[\w.\-+%]{1,64}@[\w.\-]{2,255}\.[A-Za-z]{2,10}`)

	// privateKeyRe is a regular expression that matches PEM/OpenSSH private key blocks used to sign Salesforce JWT claims.
	privateKeyRe = regexp.MustCompile(`(?s)-----BEGIN (?:OPENSSH|RSA|DSA|EC|ED25519|ENCRYPTED)? ?PRIVATE KEY-----.*?-----END (?:OPENSSH|RSA|DSA|EC|ED25519|ENCRYPTED)? ?PRIVATE KEY-----`)
)

// NewDetector returns a detector that matches Salesforce OAuth2 client credentials.
func NewDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxIDLength, maxPrivateKeyLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(clientIDRe),
			ntuple.FindAllMatches(usernameRe),
			ntuple.FindAllMatches(privateKeyRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return Credentials{ID: string(ms[0].Value), Username: string(ms[1].Value), PrivateKey: string(ms[2].Value)}, true
		},
	}
}
