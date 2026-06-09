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
