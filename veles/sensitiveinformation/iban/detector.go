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

// Package iban implements IBAN detection logic.
package iban

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const maxSecretLength = 41

var ibanRe = regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)\b`)

var countryLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28,
	"BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 16, "BR": 29, "BY": 28,
	"CH": 21, "CR": 22, "CY": 28, "CZ": 24,
	"DE": 22, "DJ": 27, "DK": 18, "DO": 28,
	"EE": 20, "EG": 29, "ES": 24,
	"FI": 18, "FO": 18, "FR": 27,
	"GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
	"HR": 21, "HU": 28,
	"IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
	"JO": 30,
	"KW": 30, "KZ": 20,
	"LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25,
	"MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30,
	"NL": 18, "NO": 15,
	"PK": 24, "PL": 28, "PS": 29, "PT": 25,
	"QA": 29,
	"RO": 24, "RS": 22, "RU": 33,
	"SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28,
	"TL": 23, "TN": 24, "TR": 26,
	"UA": 29,
	"VA": 22, "VG": 24,
	"XK": 20,
}

// Most examples taken from https://www.citibank.pl/poland/citidirect/polish/pdf/iban.pdf
var commonExamples = map[string]struct{}{
	"AL47212110090000000235698741":    {},
	"AD1200012030200359100100":        {},
	"SA0380000000608010167519":        {},
	"AT611904300234573201":            {},
	"BE68539007547034":                {},
	"BA391290079401028494":            {},
	"BG80BNBG96611020345678":          {},
	"HR1210010051863000160":           {},
	"CY17002001280000001200527600":    {},
	"ME25505000012345678951":          {},
	"DK5000400440116243":              {},
	"EE382200221020145685":            {},
	"FI2112345600000785":              {},
	"FR1420041010050500013M02606":     {},
	"GI75NWBK000000007099453":         {},
	"GR1601101250000000012300695":     {},
	"GE29NB0000000101904917":          {},
	"ES9121000418450200051332":        {},
	"NL91ABNA0417164300":              {},
	"IE29AIBK93115212345678":          {},
	"IS140159260076545510730339":      {},
	"IL620108000000099999999":         {},
	"KZ86125KZT5004100100":            {},
	"KW81CBKU0000000000001234560101":  {},
	"LB62099900000001001901229114":    {},
	"LI21088100002324013AA":           {},
	"LT121000011101001000":            {},
	"LU280019400644750000":            {},
	"LV80BANK0000435195001":           {},
	"MK07250120000058984":             {},
	"MT84MALT011000012345MTLCAST001S": {},
	"MR1300020001010000123456753":     {},
	"MU17BOMM0101101030300200000MUR":  {},
	"MC1112739000700011111000H79":     {},
	"DE89370400440532013000":          {},
	"NO9386011117947":                 {},
	"PL61109010140000071219812874":    {},
	"PT50000201231234567890154":       {},
	"CZ6508000000192000145399":        {},
	"SK3112000000198742637541":        {},
	"RO49AAAA1B31007593840000":        {},
	"SM86U0322509800000000270100":     {},
	"RS35260005601001611379":          {},
	"SI56191000000123438":             {},
	"CH9300762011623852957":           {},
	"SE4550000000058398257466":        {},
	"TN5910006035183598478831":        {},
	"TR330006100519786457841326":      {},
	"HU42117730161111101800000000":    {},
	"GB29NWBK60161331926819":          {},
	"IT60X0542811101000000123456":     {},

	// Additional very common one
	"GB82WEST12345698765432": {},
}

// NewDetector returns a Detector that finds International Bank Account Numbers (IBANs).
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen: maxSecretLength,
		Re:     ibanRe,
		FromMatch: func(b []byte, _ bool) (sensitiveinformation.SensitiveInformation, bool) {
			if !validIBAN(string(b)) {
				return sensitiveinformation.SensitiveInformation{}, false
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "International Bank Account Number",
					Sensitivity: sensitiveinformation.SensitivityLevelLow,
				},
				Likelihood: sensitiveinformation.LikelihoodVeryLikely,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}

func validIBAN(s string) bool {
	iban := strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if _, ok := commonExamples[iban]; ok {
		return false
	}

	if want, ok := countryLengths[iban[:2]]; !ok || len(iban) != want {
		return false
	}

	// https://en.wikipedia.org/wiki/International_Bank_Account_Number#Validating_the_IBAN
	rearranged := iban[4:] + iban[:4]
	mod := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			mod = (mod*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			v := int(r-'A') + 10
			mod = (mod*100 + v) % 97
		default:
			return false
		}
	}

	return mod == 1
}
