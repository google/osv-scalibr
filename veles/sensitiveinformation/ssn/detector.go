package ssn

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const maxSecretLength = 9

// SSN has format ddd-dd-dddd
// SSN CANNOT start with 666
// SSN's first segment cannot be between 900-999
// SSN's segment cannot be all 0s
var ssnRe = regexp.MustCompile("(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}")

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
