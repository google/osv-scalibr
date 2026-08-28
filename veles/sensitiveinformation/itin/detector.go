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

// Package itin implements ITIN detection logic.
package itin

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const (
	maxSecretLength   = 11
	contextWindowSize = 64
)

var itinRe = regexp.MustCompile(`\b(9\d{8}|9\d{2}-\d{2}-\d{4}|9\d{2} \d{2} \d{4})\b`)

var itinKeywords = simpleregex.KeywordsRe([]string{
	`\bitin(?:_(?:number|num|no))?\b`,
	`\btin(?:_(?:number|num|no))?\b`,
	`individual(?:\s|[-_])*tax`,
	`individual(?:\s|[-_])*taxpayer`,
	`individual(?:\s|[-_])*taxpayer\s*id`,
	`individual(?:\s|[-_])*taxpayer\s*identification`,
	`taxpayer(?:\s|[-_])*identification\s*(?:number|num|no|#)?`,
	`tax(?:\s|[-_])*identification\s*(?:number|num|no|#)?`,
	// Form W-7 is also used to renew existing ITINs.
	// https://www.irs.gov/forms-pubs/about-form-w-7
	`form(?:\s|[-_])*w-?7`,
})

// NewDetector returns a Detector that finds US Individual Taxpayer Identification Numbers (ITINs).
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen:              maxSecretLength,
		Re:                  itinRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		KeywordsRe:          itinKeywords,
		FromMatch: func(b []byte, matchedKeywords [][]byte) (sensitiveinformation.SensitiveInformation, bool) {
			itin := string(b)
			if !validItin(itin) {
				return sensitiveinformation.SensitiveInformation{}, false
			}

			likelihood := sensitiveinformation.LikelihoodUnlikely
			if len(matchedKeywords) > 0 {
				likelihood = sensitiveinformation.LikelihoodLikely
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER",
					Sensitivity: sensitiveinformation.SensitivityLevelHigh,
				},
				Likelihood: likelihood,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}

// Format requirements can found on Wikipedia:
// https://en.wikipedia.org/wiki/Individual_Taxpayer_Identification_Number
func validItin(s string) bool {
	normalized := strings.ReplaceAll(s, "-", "")
	secondSection := normalized[3:5]

	return secondSection != "89" &&
		secondSection != "93" &&
		((secondSection >= "50" && secondSection <= "65") ||
			(secondSection >= "70" && secondSection <= "99"))
}
