// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package uspassportnumber implements logic for detecting US passport numbers
package uspassportnumber

import (
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const (
	maxPassportNumberLen = 9
	maxKeywordLen        = 20
	contextWindowSize    = 32
)

var (
	keywordsRe = simpleregex.KeywordsRe([]string{
		`\b\w*passport\w*\b`,
		`\b\w*travel\w*\b`,
		`\b\w*document\w*\b`,
	})
	passportNumberRe = regexp.MustCompile(`\b[A-Za-z][0-9]{8}\b`)
)

// NewDetector returns a Detector, that finds US Passport Numbers
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen:              max(maxKeywordLen, maxPassportNumberLen),
		Re:                  passportNumberRe,
		KeywordsRe:          keywordsRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		FromMatch: func(blob []byte, keywordMatch bool) (sensitiveinformation.SensitiveInformation, bool) {
			likelihood := sensitiveinformation.LikelihoodUnlikely
			if keywordMatch {
				likelihood = sensitiveinformation.LikelihoodVeryLikely
			}

			return sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "US_PASSPORT_NUMBER",
					Sensitivity: sensitiveinformation.SensitivityLevelHigh,
				},
				Likelihood: likelihood,
				Raw:        bytes.Clone(blob),
			}, true
		},
	}
}
