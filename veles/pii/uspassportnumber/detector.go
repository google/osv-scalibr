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

package uspassportnumber

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	maxPassportNumberLen = 9
	maxKeywordLen        = 20
)

var (
	keywordRe        = regexp.MustCompile(`(?i)\b\w*(?:passport|document|travel)\w*\b`)
	passportNumberRe = regexp.MustCompile(`\b[A-Za-z][0-9]{8}\b`)
)

// A match is considered successful only if the context keyword is also matched near to the value
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxPassportNumberLen,
		MaxDistance:   veles.KiB, // The context keyword should be within 1Kb of data from the detected value
		FindA:         pair.FindAllMatches(passportNumberRe),
		FindB:         pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return USPassportNumber{Value: string(p.A.Value)}, true
		},
	}
}
