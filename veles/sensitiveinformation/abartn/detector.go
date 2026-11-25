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

// Package abartn implements ABA routing transit number (RTN) detection logic.
package abartn

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
	contextWindowSize = 32
)

// An RTN is 9 digits in the MICR format "XXXXYYYYC", optionally written as
// "XXXX-YYYY-C". The first two digits must be in one of the following ranges:
//   - 00 (US Government)
//   - 01-12 (Federal Reserve districts)
//   - 21-32 (thrift institutions),
//   - 61-72 (electronic transactions)
//   - 80 (traveler's cheques)
//
// https://en.wikipedia.org/wiki/ABA_routing_transit_number
var rtnRe = regexp.MustCompile(`\b(?:0\d|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)(?:\d{7}|\d{2}-\d{4}-\d)\b`)

var keywordsRe = simpleregex.KeywordsRe([]string{
	`(?:\b|_|bank)aba(?:\b|_|number)`,
	`(?:\b|_|aba|bank|customer)rtn(?:\b|_|number)`,
	`(?:\b|_|check)micr(?:\b|_|line)`,
	`routing(?:\b|_|number|transit)`,
	`transit(?:\b|_|number)`,
})

// placeholders are test RTNs that are documented for public use.
// They are not sensitive, so the detector does not report them.
var placeholders = map[string]struct{}{
	// Stripe test routing number for US bank accounts (ACH Direct Debit).
	// https://docs.stripe.com/testing
	"110000000": {},
}

// validChecksum reports whether the RTN check digit is valid.
// https://en.wikipedia.org/wiki/ABA_routing_transit_number#Check_digit
func validChecksum(b []byte) bool {
	weights := [3]int{3, 7, 1}
	sum, i := 0, 0
	for _, c := range b {
		if c == '-' {
			continue
		}
		sum += int(c-'0') * weights[i%3]
		i++
	}
	return sum%10 == 0
}

// NewDetector returns a Detector, that finds ABA routing transit numbers (RTNs)
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen:              maxSecretLength,
		Re:                  rtnRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		KeywordsRe:          keywordsRe,
		FromMatch: func(b []byte, contextMatch bool) (sensitiveinformation.SensitiveInformation, bool) {
			if _, ok := placeholders[strings.ReplaceAll(string(b), "-", "")]; ok {
				return sensitiveinformation.SensitiveInformation{}, false
			}

			likelihood := sensitiveinformation.LikelihoodUnlikely

			if contextMatch {
				likelihood = sensitiveinformation.LikelihoodLikely
			}

			if validChecksum(b) {
				if likelihood == sensitiveinformation.LikelihoodUnlikely {
					likelihood = sensitiveinformation.LikelihoodLikely
				} else {
					likelihood = sensitiveinformation.LikelihoodVeryLikely
				}
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "US_BANK_ROUTING_TRANSIT_NUMBER_MICR",
					Sensitivity: sensitiveinformation.SensitivityLevelModerate,
				},
				Likelihood: likelihood,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}
