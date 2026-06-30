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
	"slices"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

// issuerRange describes a single issuer identification number (IIN) prefix
// range for a payment card network together with the card number lengths that
// network currently issues.
//
// A network can span multiple entries when it owns several disjoint prefix
// ranges (e.g. Mastercard owns both 51–55 and 2221–2720). The [lowIIN, highIIN]
// bounds are inclusive and must have the same number of digits, which also
// defines how many leading digits of a card number are compared.
type issuerRange struct {
	lowIIN  string
	highIIN string
	// lengths lists every valid card number length for this range. Lengths are
	// frequently non-contiguous (e.g. Visa is 13, 16, 19), so they are listed
	// explicitly; lengthRange is a convenience for contiguous spans.
	lengths []int
}

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

// issuerRanges holds every payment card network currently marked as active in
// the IIN table at
// http://en.wikipedia.org/wiki/Payment_card_number#Issuer_identification_number_(IIN)
//
// Networks that no longer issue cards (Bankcard, Diners Club enRoute, Laser,
// NPS Pridnestrovie, Solo, Switch, Visa Electron) are intentionally omitted.
var issuerRanges = []issuerRange{
	// American Express
	{lowIIN: "34", highIIN: "34", lengths: []int{15}},
	{lowIIN: "37", highIIN: "37", lengths: []int{15}},
	// China T-Union
	{lowIIN: "31", highIIN: "31", lengths: []int{19}},
	// China UnionPay
	{lowIIN: "62", highIIN: "62", lengths: lengthRange(16, 19)},
	// Diners Club International
	{lowIIN: "30", highIIN: "30", lengths: lengthRange(14, 19)},
	{lowIIN: "36", highIIN: "36", lengths: lengthRange(14, 19)},
	{lowIIN: "38", highIIN: "39", lengths: lengthRange(14, 19)},
	// Diners Club US & Canada
	{lowIIN: "55", highIIN: "55", lengths: []int{16}},
	// Discover
	{lowIIN: "6011", highIIN: "6011", lengths: lengthRange(16, 19)},
	{lowIIN: "644", highIIN: "649", lengths: lengthRange(16, 19)},
	{lowIIN: "65", highIIN: "65", lengths: lengthRange(16, 19)},
	{lowIIN: "622126", highIIN: "622925", lengths: lengthRange(16, 19)}, // China UnionPay co-branded
	// UkrCart
	{lowIIN: "60400100", highIIN: "60420099", lengths: lengthRange(16, 19)},
	// RuPay
	{lowIIN: "60", highIIN: "60", lengths: []int{16}},
	{lowIIN: "65", highIIN: "65", lengths: []int{16}},
	{lowIIN: "81", highIIN: "82", lengths: []int{16}},
	{lowIIN: "508", highIIN: "508", lengths: []int{16}},
	{lowIIN: "353", highIIN: "353", lengths: []int{16}}, // RuPay-JCB co-branded
	{lowIIN: "356", highIIN: "356", lengths: []int{16}}, // RuPay-JCB co-branded
	// InterPayment
	{lowIIN: "636", highIIN: "636", lengths: lengthRange(16, 19)},
	// InstaPayment
	{lowIIN: "637", highIIN: "639", lengths: []int{16}},
	// JCB
	{lowIIN: "3528", highIIN: "3589", lengths: lengthRange(16, 19)},
	// LankaPay (JCB co-branded)
	{lowIIN: "357111", highIIN: "357111", lengths: []int{16}},
	// Maestro UK
	{lowIIN: "6759", highIIN: "6759", lengths: lengthRange(12, 19)},
	{lowIIN: "676770", highIIN: "676770", lengths: lengthRange(12, 19)},
	{lowIIN: "676774", highIIN: "676774", lengths: lengthRange(12, 19)},
	// Maestro
	{lowIIN: "5018", highIIN: "5018", lengths: lengthRange(12, 19)},
	{lowIIN: "5020", highIIN: "5020", lengths: lengthRange(12, 19)},
	{lowIIN: "5038", highIIN: "5038", lengths: lengthRange(12, 19)},
	{lowIIN: "5893", highIIN: "5893", lengths: lengthRange(12, 19)},
	{lowIIN: "6304", highIIN: "6304", lengths: lengthRange(12, 19)},
	{lowIIN: "6759", highIIN: "6759", lengths: lengthRange(12, 19)},
	{lowIIN: "6761", highIIN: "6763", lengths: lengthRange(12, 19)},
	// Dankort
	{lowIIN: "5019", highIIN: "5019", lengths: []int{16}},
	{lowIIN: "4571", highIIN: "4571", lengths: []int{16}}, // Visa co-branded
	// Mir
	{lowIIN: "2200", highIIN: "2204", lengths: lengthRange(16, 19)},
	// BORICA
	{lowIIN: "2205", highIIN: "2205", lengths: []int{16}},
	// Mastercard
	{lowIIN: "51", highIIN: "55", lengths: []int{16}},
	{lowIIN: "2221", highIIN: "2720", lengths: []int{16}},
	// Troy
	{lowIIN: "65", highIIN: "65", lengths: []int{16}}, // Discover co-branded
	{lowIIN: "9792", highIIN: "9792", lengths: []int{16}},
	// Visa
	{lowIIN: "4", highIIN: "4", lengths: []int{13, 16, 19}},
	// UATP
	{lowIIN: "1", highIIN: "1", lengths: []int{15}},
	// Verve
	{lowIIN: "506099", highIIN: "506198", lengths: []int{16, 18, 19}},
	{lowIIN: "650002", highIIN: "650027", lengths: []int{16, 18, 19}},
	{lowIIN: "507865", highIIN: "507964", lengths: []int{16, 18, 19}},
	// Uzcard
	{lowIIN: "8600", highIIN: "8600", lengths: []int{16}},
	{lowIIN: "5614", highIIN: "5614", lengths: []int{16}},
	// HUMO
	{lowIIN: "9860", highIIN: "9860", lengths: []int{16}},
	// GPN
	{lowIIN: "1946", highIIN: "1946", lengths: []int{16, 18, 19}}, // BNI cards
	{lowIIN: "50", highIIN: "50", lengths: []int{16, 18, 19}},
	{lowIIN: "56", highIIN: "56", lengths: []int{16, 18, 19}},
	{lowIIN: "58", highIIN: "58", lengths: []int{16, 18, 19}},
	{lowIIN: "60", highIIN: "63", lengths: []int{16, 18, 19}},
	// Napas
	{lowIIN: "9704", highIIN: "9704", lengths: []int{16, 19}},
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
	// https://en.wikipedia.org/wiki/Luhn_algorithm#Pseudocode_implementation
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

// lengthRange returns the inclusive integer range [lo, hi] as a slice, for
// declaring contiguous card number lengths such as "16–19".
//
// hi is currently always 19, but is kept as a parameter so the call sites read
// as the "lo–hi" ranges they mirror from the source table.
//
//nolint:unparam // hi is intentionally explicit for readability at call sites.
func lengthRange(lo, hi int) []int {
	out := make([]int, 0, hi-lo+1)
	for n := lo; n <= hi; n++ {
		out = append(out, n)
	}
	return out
}

// hasCommonIssuerAndLength reports whether digits matches the IIN prefix and a
// valid length of any currently active payment card network. It is used to
// raise detection confidence when an issuer can be positively identified.
func hasCommonIssuerAndLength(digits string) bool {
	length := len(digits)
	for _, r := range issuerRanges {
		if prefixInRange(digits, r.lowIIN, r.highIIN) && slices.Contains(r.lengths, length) {
			return true
		}
	}
	return false
}

func prefixInRange(digits string, lower string, upper string) bool {
	prefixLen := len(lower)
	if len(digits) < prefixLen {
		return false
	}
	prefix := digits[:prefixLen]

	return prefix >= lower && prefix <= upper
}
