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

// Package atin implements ATIN detection logic.
package atin

import (
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const (
	maxSecretLength   = 11
	contextWindowSize = 64
)

// https://www.irs.gov/individuals/adoption-taxpayer-identification-number
// https://www.irs.gov/irm/part3/irm_03-013-040 (See 3.13.40.2.1 (05-04-2023) Characteristics of the ATIN)
var atinRe = regexp.MustCompile(`\b(9\d{2}93\d{4}|9\d{2}-93-\d{4}|9\d{2} 93 \d{4})\b`)

var atinKeywords = simpleregex.KeywordsRe([]string{
	`\batin\b`,
	`\batin(?:\s|[-_])*(?:number|num|no\b|#)`,
	`adoption(?:\s|[-_])*taxpayer(?:\s|[-_])*identification(?:\s|[-_])*number`,
	`adoption(?:\s|[-_])*taxpayer(?:\s|[-_])*identification`,
	`adoption(?:\s|[-_])*tax(?:\s|[-_])*identification(?:\s|[-_])*number`,
	`adoption(?:\s|[-_])*tax(?:\s|[-_])*id`,
	`adoption(?:\s|[-_])*taxpayer(?:\s|[-_])*id`,
	`adoption(?:\s|[-_])*tin`,
	`irs(?:\s|[-_])*atin`,
	`form(?:\s|[-_])*w-7a`,
	`w-7a`,
})

// NewDetector returns a Detector, that finds US Adoption Taxpayer Identification Number (ATIN)
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen:              maxSecretLength,
		Re:                  atinRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		KeywordsRe:          atinKeywords,
		FromMatch: func(b []byte, contextMatch bool) (sensitiveinformation.SensitiveInformation, bool) {
			likelihood := sensitiveinformation.LikelihoodUnlikely
			if contextMatch {
				likelihood = sensitiveinformation.LikelihoodLikely
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "ADOPTION_TAXPAYER_IDENTIFICATION_NUMBER",
					Sensitivity: sensitiveinformation.SensitivityLevelHigh,
				},
				Likelihood: likelihood,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}
