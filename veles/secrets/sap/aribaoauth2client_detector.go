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
	// maxAribaIDLength is the maximum length of a valid client ID.
	// There is not documented length.
	// Verification by free trial confirms it is an UUID-like string which is either 32 (without hypens) or 36 (with hypens) symbols long.
	// Reference:
	// https://help.sap.com/docs/ariba-apis/help-for-sap-ariba-developer-portal/initial-access-token-requests
	// I have selected 50 as an upperbound because we're doing contextual matching, and we need to account for prefixes and spaces.
	maxAribaIDLength = 50

	// maxAribaSecretLength is the maximum length of a valid client secret.
	// There is not documented length.
	// Verification by free trial confirms it is a random string which is exactly 32 symbols long.
	// I have selected 50 as an upperbound because we're doing contextual matching, and we need to account for prefixes and spaces.
	maxAribaSecretLength = 50
)

var (
	// aribaClientIDRe is a regular expression that matches SAP Ariba OAuth2 Client IDs.
	// Client ID is an UUID-like string.
	// References:
	// https://help.sap.com/docs/ariba-apis/help-for-sap-ariba-developer-portal/initial-access-token-requests
	aribaClientIDRe = regexp.MustCompile(`(?i)\bclient[_-]?id\b\s*[:=]?\s*([a-zA-Z0-9-]{32,36})\b`)

	// aribaClientSecretRe is a regular expression that matches SAP Ariba OAuth2 Client Secrets.
	// Verification by free trial confirms it is a random string which is exactly 32 symbols long.
	aribaClientSecretRe = regexp.MustCompile(`(?i)\bclient[_-]?secret\b\s*[:=]?\s*([a-zA-Z0-9]{32})\b`)
)

// NewSAPAribaOAuth2ClientCredentialsDetector returns a detector that matches SAP Ariba OAuth2 Client Credentials.
func NewSAPAribaOAuth2ClientCredentialsDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxAribaIDLength, maxAribaSecretLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatchesGroup(aribaClientIDRe),
			ntuple.FindAllMatchesGroup(aribaClientSecretRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return AribaOAuth2ClientCredentials{ID: string(ms[0].Value), Secret: string(ms[1].Value)}, true
		},
	}
}
