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

package squareapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	maxKeyLength = 124
	// maxDistance is the maximum distance between Square API Key and keywords
	// to be considered for pairing.
	maxDistance = 50
)

var (
	// tokenRe matches both Square Personal Access Tokens (EAAA...)
	// and OAuth Application Secrets (sq0csp-...).
	tokenRe = regexp.MustCompile(`\b(EAAA[\w\-\+\=]{60}|sq0csp-[A-Za-z0-9_-]{43})\b`)

	// keywordRe matches Square related keywords.
	keywordRe = regexp.MustCompile(`(?i)(square|SQUARE_ACCESS_TOKEN|SQUARE_APPLICATION_SECRET)`)
)

// NewDetector returns a detector that matches Square keywords and API Key secret.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxKeyLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(tokenRe),
		FindB:         pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return SquareAPIKey{Key: string(p.A.Value)}, true
		},
	}
}
