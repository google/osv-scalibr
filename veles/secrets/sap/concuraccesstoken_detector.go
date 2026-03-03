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
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

// NewSAPConcurAccessTokenDetector returns a detector that matches SAP Concur Access Token.
func NewSAPConcurAccessTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxAccessTokenLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			findValidSAPConcurTokens(),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return ConcurAccessToken{Token: string(ms[0].Value)}, true
		},
	}
}

func findValidSAPConcurTokens() ntuple.Finder {
	return func(data []byte) []ntuple.Match {
		matches := accessTokenRe.FindAllSubmatchIndex(data, -1)
		results := make([]ntuple.Match, 0, len(matches))

		for _, idx := range matches {
			// idx layout:
			// [fullStart, fullEnd, g1Start, g1End]

			if len(idx) < 4 || idx[2] < 0 || idx[3] < 0 {
				continue
			}

			fullStart := idx[0]
			fullEnd := idx[1]
			jwtBytes := data[idx[2]:idx[3]]

			if len(jwtBytes) > maxJWTLength {
				continue
			}

			payload, ok := parseJWTPayload(jwtBytes)
			if !ok {
				continue
			}

			iss, ok := payload[payloadIssuerKey].(string)
			if !ok || !isValidSAPConcurIssuer(iss) {
				continue
			}

			results = append(results, ntuple.Match{
				Start: fullStart,
				End:   fullEnd,
				Value: jwtBytes,
			})
		}

		return results
	}
}

// isValidSAPIssuer checks if issuer contains SAP Concur String
func isValidSAPConcurIssuer(iss string) bool {
	return strings.Contains(iss, "concur.com")
}
