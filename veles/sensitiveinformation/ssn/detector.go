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
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const maxSecretLength = 11

// SSN has format ddd-dd-dddd
var ssnRe = regexp.MustCompile(`[0-8]\d{2}-\d{2}-\d{4}`)

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
				Raw:        b,
			}

			return finding, true
		},
	}
}

// SSN CANNOT start with 666
// SSN's first segment cannot be between 900-999
// SSN's segment cannot be all 0s
func validSSN(s string) bool {
	if !ssnRe.MatchString(s) {
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
