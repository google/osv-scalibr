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

package bitwardenapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	maxIDLength     = 100
	maxSecretLength = 100
	// maxDistance is the maximum distance between Client ID and Client Secret.
	maxDistance = 1024
)

var (
	// clientIDRe matches Bitwarden Client IDs (user. or organization. prefix).
	clientIDRe = regexp.MustCompile(`\b((?:user|organization)\.[a-zA-Z0-9.-]{30,})\b`)
	// clientSecretRe matches Bitwarden Client Secrets (random alphanumeric).
	clientSecretRe = regexp.MustCompile(`\b([a-zA-Z0-9.]{30,})\b`)
)

// NewDetector returns a detector that matches Bitwarden Client ID and Secret pairs.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxIDLength, maxSecretLength),
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(clientIDRe),
		FindB:         pair.FindAllMatches(clientSecretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return BitwardenAPIKey{
				ClientID:     string(p.A.Value),
				ClientSecret: string(p.B.Value),
			}, true
		},
	}
}
