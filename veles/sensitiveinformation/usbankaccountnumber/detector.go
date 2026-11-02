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

// Package usbankaccountnumber implements US bank account number detection logic.
package usbankaccountnumber

import (
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const (
	maxSecretLength   = 17
	contextWindowSize = 32
)

var accountNumberRe = regexp.MustCompile(`\b\d{8,17}\b`)

var keywordsRe = simpleregex.KeywordsRe([]string{
	`bank`,
	`account`,
	`us`,
	// JP Morgan
	`\bj[.\s]*p\.?(?:\s|[-_])*morgan\b`,
	// Morgan Chase
	`morgan(?:\s|[-_])*chase\b`,
	// Chase"
	`\bchase\b`,
	// Bank of America
	`\bbofa\b`,
	// Wells Fargo
	`wells(?:\s|[-_])*fargo`,
	// Capital One
	`capital(?:\s|[-_])*one`,
	// Goldman Sachs
	`goldman(?:\s|[-_])*sachs`,
	// Morgan Stanley
	`morgan(?:\s|[-_])*stanley`,
})

// NewDetector returns a Detector, that finds US bank account numbers
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen:              maxSecretLength,
		Re:                  accountNumberRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		KeywordsRe:          keywordsRe,
		FromMatch: func(b []byte, contextMatch bool) (sensitiveinformation.SensitiveInformation, bool) {
			likelihood := sensitiveinformation.LikelihoodUnlikely
			if contextMatch {
				likelihood = sensitiveinformation.LikelihoodLikely
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "US_BANK_ACCOUNT_NUMBER",
					Sensitivity: sensitiveinformation.SensitivityLevelHigh,
				},
				Likelihood: likelihood,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}
