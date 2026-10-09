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

// Package usnewpassportnumber implements logic for detecting the new version US passport numbers
package usnewpassportnumber

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"

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
	specifierKeywords = []string{
		`us`,
		`usa`,
		`states`,
		`america`,
	}
	baseKeywords = []string{
		`pass`,
		`travel`,
		`doc`,
	}

	keywordsRe       *regexp.Regexp
	passportNumberRe = regexp.MustCompile(`\b[A-Za-z][0-9]{8}\b`)
)

func hasSpecifier(keyword []byte) bool {
	keywordStr := strings.ToLower(string(keyword))
	for _, specifier := range specifierKeywords {
		if strings.Contains(keywordStr, specifier) {
			return true
		}
	}
	return false
}

func init() {
	specifierOrRePattern := strings.Join(specifierKeywords, "|")
	var keywordsRePattern []string
	for _, keyword := range baseKeywords {
		keywordsRePattern = append(keywordsRePattern,
			fmt.Sprintf(`(?:(?:%s)[\w _-]*)?%s(?:[\w _-]*(?:%s))?`, specifierOrRePattern, keyword, specifierOrRePattern))
	}

	keywordsRe = simpleregex.KeywordsRe(keywordsRePattern)
}

// NewDetector returns a Detector, that finds new versions of US passport numbers
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen:              max(maxKeywordLen, maxPassportNumberLen),
		Re:                  passportNumberRe,
		KeywordsRe:          keywordsRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		FromMatch: func(blob []byte, matchedKeywords [][]byte) (sensitiveinformation.SensitiveInformation, bool) {
			likelihood := sensitiveinformation.LikelihoodUnlikely
			if len(matchedKeywords) > 0 {
				likelihood = sensitiveinformation.LikelihoodLikely
				if slices.ContainsFunc(matchedKeywords, hasSpecifier) {
					likelihood = sensitiveinformation.LikelihoodVeryLikely
				}
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
