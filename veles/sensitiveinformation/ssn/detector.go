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

package ssn

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const maxSecretLength = 11

// SSN has format ddd-dd-dddd
// SSN CANNOT start with 666
// SSN's first segment cannot be between 900-999
// SSN's segment cannot be all 0s
var ssnRe = regexp.MustCompile("(00[1-9]|0[1-9][0-9]|[1-5][0-9]{2}|6[0-5][0-9]|66[0-5]|66[7-9]|[78][0-9]{2})-(0[1-9]|[1-9][0-9])-(000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})")

// NewDetector() returns a Detector, that finds US Social Security Numbers (SSNs)
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen: maxSecretLength,
		Re:     ssnRe,
		FromMatch: func(b []byte) (sensitiveinformation.SensitiveInformation, bool) {
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
