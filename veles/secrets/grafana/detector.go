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

package grafana

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)
//We allow a bit of extra length for potential variations.
const maxSATokenLen = 56     //typically around 50 chars
const maxCloudTokenLen = 130 // typically around 120 chars
const maxStackLen = 40       // typically around 30 chars

const maxDistance = 100      // Maximum distance between tokens to consider them a match.

var saTokenRe = regexp.MustCompile(`glsa_[A-Za-z0-9_-]{30,50}`)  // No fixed length, but 50 is a reasonable upper bound based on observed tokens.    
var cloudTokenRe = regexp.MustCompile(`glc_[0-9a-zA-Z+/=]{110,130}`) // No fixed length, but 130 is a reasonable upper bound based on observed tokens.

// Stack names can vary widely, typically alphanumeric chars and may include hyphens or underscores.
var stackRe = regexp.MustCompile(`[a-zA-Z0-9]+.grafana.net`)

// NewServiceAccountTokenDetector returns a detector that matches Grafana Service Account Tokens.
func NewServiceAccountTokenDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxSATokenLen, maxStackLen), MaxDistance: maxDistance,
		FindA: pair.FindAllMatches(saTokenRe),
		FindB: pair.FindAllMatches(stackRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return ServiceAccountToken{Token: string(p.A.Value), Stack: string(p.B.Value)}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A == nil {
				return nil, false
			}
			return ServiceAccountToken{Token: string(p.A.Value)}, true
		},
	}
}

// NewCloudTokenDetector returns a detector that matches Grafana Cloud Tokens.
func NewCloudTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxCloudTokenLen,
		Re:     cloudTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return CloudToken{Token: string(b)}, true
		},
	}
}
