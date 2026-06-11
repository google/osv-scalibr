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

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const maxSecretLength = 11

// https://www.protecto.ai/blog/personal-dataset-sample-u-s-social-security-number-ssn-download-pii-data-examples-2/
// https://www.ssa.gov/history/ssn/geocard.html
var ssnRe = regexp.MustCompile(`\b[0-8]\d{2}-\d{2}-\d{4}\b`)

var commonExamples = map[string]struct{}{
	"123-45-6789": {},

	"111-11-1111": {},
	"222-22-2222": {},
	"333-33-3333": {},
	"444-44-4444": {},
	"555-55-5555": {},
	"777-77-7777": {},
	"888-88-8888": {},
	"999-99-9999": {},

	// https://www.ssa.gov/history/ssn/misused.html
	"078-05-1120": {},
}

// NewDetector returns a Detector, that finds US Social Security Numbers (SSNs)
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen: maxSecretLength,
		Re:     ssnRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			ssn := string(b)
			if !validSSN(ssn) {
				return nil, false
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "Social Security Number",
					Sensitivity: sensitiveinformation.SensitivityLevelModerate,
				},
				Likelihood: sensitiveinformation.LikelihoodLikely,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}

func validSSN(s string) bool {
	if !ssnRe.MatchString(s) {
		return false
	}

	if _, ok := commonExamples[s]; ok {
		return false
	}

	area := s[0:3]
	group := s[4:6]
	serial := s[7:11]

	return area != "000" &&
		area != "666" &&
		group != "00" &&
		serial != "0000"
}
