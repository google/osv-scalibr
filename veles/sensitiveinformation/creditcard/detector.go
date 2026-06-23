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
	"strconv"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const maxSecretLength = 23
const contextWindowSize = 32

var creditCardRe = regexp.MustCompile(`\b(?:\d{12,19}|\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?|\d{4}[ -]\d{6}[ -]\d{5})\b`)

var keywordsRe = simpleregex.KeywordsRe([]string{
	`\bcreditcard\b`,
	`\bcredit\b`,
	`\bcard\b`,
	`\bcvc\b`,
	`\bcvv\b`,
	`\bcvv2\b`,
	`\bvisa\b`,
	`\bmaster\b`,
	`\bmastercard\b`,
	`\bcardholder\b`,
})

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
		MaxLen:              maxSecretLength,
		Re:                  creditCardRe,
		KeywordsRe:          keywordsRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		FromMatch: func(b []byte, keywordMatch bool) (sensitiveinformation.SensitiveInformation, bool) {
			if !validCreditCardNumber(b) {
				return sensitiveinformation.SensitiveInformation{}, false
			}

			likelihood := sensitiveinformation.LikelihoodUnlikely
			if keywordMatch {
				likelihood = sensitiveinformation.LikelihoodLikely
				if hasCommonIssuerAndLength(normalizedDigits(b)) {
					likelihood = sensitiveinformation.LikelihoodVeryLikely
				}
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "CREDIT_CARD_NUMBER",
					Sensitivity: sensitiveinformation.SensitivityLevelHigh,
				},
				Likelihood: likelihood,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}

func validCreditCardNumber(b []byte) bool {
	digits := normalizedDigits(b)
	if len(digits) < 12 || len(digits) > 19 {
		return false
	}

	if _, ok := commonExamples[digits]; ok {
		return false
	}

	// Filter out credit cards with all the same digits
	allSame := true
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
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

func normalizedDigits(b []byte) string {
	digits := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			digits = append(digits, c)
		case c == ' ' || c == '-':
		default:
			return ""
		}
	}
	return string(digits)
}

func hasCommonIssuerAndLength(digits string) bool {
	length := len(digits)
	return (prefixInRange(digits, 4, 4) && (length == 13 || length == 16 || length == 19)) ||
		(prefixInRange(digits, 51, 55) && length == 16) ||
		(prefixInRange(digits, 2221, 2720) && length == 16) ||
		((prefixInRange(digits, 34, 34) || prefixInRange(digits, 37, 37)) && length == 15) ||
		((prefixInRange(digits, 6011, 6011) || prefixInRange(digits, 644, 649) || prefixInRange(digits, 65, 65) || prefixInRange(digits, 622126, 622925)) && (length == 16 || length == 19)) ||
		(prefixInRange(digits, 3528, 3589) && length >= 16 && length <= 19) ||
		((prefixInRange(digits, 300, 305) || prefixInRange(digits, 36, 36) || prefixInRange(digits, 38, 39)) && length == 14)
}

func prefixInRange(digits string, lower int, upper int) bool {
	prefixLen := len(strconv.Itoa(lower))
	if len(digits) < prefixLen {
		return false
	}
	prefix, err := strconv.Atoi(digits[:prefixLen])
	return err == nil && prefix >= lower && prefix <= upper
}
