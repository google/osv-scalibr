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

package gcpoauth2client

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxIDLength is the maximum length of a valid client ID.
	// There is not documented length, but examples are ~75 characters.
	// 200 is a good upper bound.
	maxIDLength = 200

	// maxSecretLength is the maximum length of a valid client secret.
	// There is not documented length, but examples are ~35 characters.
	// 100 is a good upper bound.
	maxSecretLength = 100

	// maxDistance is the maximum distance between client IDs and secrets to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB

	// maxSecretLen is the maximum length of secrets this detector can find.
	// Veles uses this to set the chunk size. Client ID and secrets should be contained within this chunk.
	maxSecretLen = maxIDLength + maxSecretLength + maxDistance
)

var (
	// clientIDRe is a regular expression that matches GCP OAuth2 client IDs.
	// There is no official documentation on the exact format of GCP OAuth2 client IDs.
	// But official docs include examples that end with .apps.googleusercontent.com:
	// - https://developers.google.com/identity/protocols/oauth2/web-server
	//
	// Other references also suggest similar formats:
	// - https://gofastmcp.com/integrations/google
	// - https://web.archive.org/web/20250418010928/https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/google_oauth2_keys
	clientIDRe = regexp.MustCompile(`[0-9]{10,15}-[a-zA-Z0-9]+\.apps\.googleusercontent\.com`)

	// clientSecretRe is a regular expression that matches GCP OAuth2 client secrets.
	// There is no clear documentation on the exact format of GCP OAuth2 client secrets.
	// But most online references suggest they start with "GOCSPX-" prefix.
	// This is a good start as it reduces false positives.
	// References:
	// - https://gofastmcp.com/integrations/google
	// - https://web.archive.org/web/20250418010928/https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/google_oauth2_keys
	clientSecretRe = regexp.MustCompile(`\bGOCSPX-[a-zA-Z0-9_-]{10,40}`)
)

// NewDetector returns a detector that matches GCP OAuth2 client credentials.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxLen: maxSecretLen, MaxDistance: maxDistance,
		FindA: pair.FindAllMatches(clientIDRe),
		FindB: pair.FindAllMatches(clientSecretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return Credentials{ID: p.A.Value, Secret: p.B.Value}, true
		},
	}
}
