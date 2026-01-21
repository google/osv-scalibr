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

package salesforceoauth

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	maxIDLength     = 124
	maxSecretLength = 64
	// maxDistance is the maximum distance between Client ID and Client Secret.
	maxDistance = 1024
)

var (
	// clientIDRe matches Salesforce OAuth Client IDs (starts with 3MVG, 84+ chars).
	clientIDRe = regexp.MustCompile(`\b3MVG[0-9A-Za-z]{80,}\b`)
	// clientSecretRe matches generic high-entropy secrets (20-60 chars).
	clientSecretRe = regexp.MustCompile(`\b[A-Za-z0-9._-]{20,60}\b`)
)

// NewDetector returns a detector that matches Salesforce Client ID and Secret pairs.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxIDLength,
		MaxDistance:   uint32(maxDistance),
		FindA:         pair.FindAllMatches(clientIDRe),
		FindB:         pair.FindAllMatches(clientSecretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return Credentials{
				ClientID:     string(p.A.Value),
				ClientSecret: string(p.B.Value),
			}, true
		},
	}
}
