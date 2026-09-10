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

// Package ssn implements SSN detection logic.
package ssn

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

// https://www.protecto.ai/blog/personal-dataset-sample-u-s-social-security-number-ssn-download-pii-data-examples-2/
// https://www.ssa.gov/history/ssn/geocard.html
var ssnRe = regexp.MustCompile(`\b(\d{9}|\d{3}-\d{2}-\d{4}|\d{3} \d{2} \d{4})\b`)

var ssnKeywordsRe = simpleregex.KeywordsRe([]string{
	`\bssn\b`,
	`social security`,
	`social security number`,
	`social security no`,
	`social security #`,
	`socialsecuritynumber`,
	`socialsecurity`,
})

var commonExamples = map[string]struct{}{
	"123456789": {},

	"111111111": {},
	"222222222": {},
	"333333333": {},
	"444444444": {},
	"555555555": {},
	"777777777": {},
	"888888888": {},
	"999999999": {},

	// https://www.ssa.gov/history/ssn/misused.html
	"078051120": {},
}

// NewDetector returns a Detector, that finds US Social Security Numbers (SSNs)
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen:              maxSecretLength,
		Re:                  ssnRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		KeywordsRe:          ssnKeywordsRe,
		FromMatch: func(b []byte, contextMatch bool) (sensitiveinformation.SensitiveInformation, bool) {
			ssn := string(b)
			if !validSSN(ssn) {
				return sensitiveinformation.SensitiveInformation{}, false
			}
			likelihood := sensitiveinformation.LikelihoodUnlikely
			if contextMatch {
				likelihood = sensitiveinformation.LikelihoodLikely
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "SOCIAL_SECURITY_NUMBER",
					Sensitivity: sensitiveinformation.SensitivityLevelHigh,
				},
				Likelihood: likelihood,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}

func validSSN(s string) bool {
	normalized := strings.NewReplacer("-", "", " ", "").Replace(s)

	if _, ok := commonExamples[normalized]; ok {
		return false
	}

	area := normalized[0:3]
	group := normalized[3:5]
	serial := normalized[5:9]

	return area[0] != '9' &&
		area != "000" &&
		area != "666" &&
		group != "00" &&
		serial != "0000"
}
