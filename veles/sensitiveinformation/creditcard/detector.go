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

// Package creditcard implements credit card number detection logic.
package creditcard

import (
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const maxSecretLength = 23

var creditCardRe = regexp.MustCompile(`\b(?:[2-6]\d{12,18}|[2-6]\d{3}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?|[2-6]\d{3}[ -]\d{6}[ -]\d{5})\b`)

var commonExamples = map[string]struct{}{
	"4111111111111111": {},
	"4242424242424242": {},
	"5555555555554444": {},
	"378282246310005":  {},
	"6011111111111117": {},
	"30569309025904":   {},
	"3530111333300000": {},
	"3566002020360505": {},
}

// NewDetector returns a Detector that finds credit card numbers.
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen: maxSecretLength,
		Re:     creditCardRe,
		FromMatch: func(b []byte, keywordMatch bool) (sensitiveinformation.SensitiveInformation, bool) {
			if !validCreditCardNumber(b) {
				return sensitiveinformation.SensitiveInformation{}, false
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "CREDIT_CARD_NUMBER",
					Sensitivity: sensitiveinformation.SensitivityLevelHigh,
				},
				Likelihood: sensitiveinformation.LikelihoodLikely,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}

func validCreditCardNumber(b []byte) bool {
	digits := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			digits = append(digits, c)
		case c == ' ' || c == '-':
		default:
			return false
		}
	}

	if _, ok := commonExamples[string(digits)]; ok {
		return false
	}

	// Filter out credit cards with all the same digits
	allSame := true
	for _, d := range digits[1:] {
		if d != digits[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}

	// Luhn check
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}

	return sum%10 == 0
}
