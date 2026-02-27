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

package alibabaaccesskey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

var (
	// AccessKey ID: Starts with LTAI followed by 17-21 alphanumeric chars
	accessIDPattern = regexp.MustCompile(`\bLTAI[A-Za-z0-9]{17,21}\b`)
	// AccessKey Secret: Fixed 30 alphanumeric characters
	secretPattern = regexp.MustCompile(`\b[A-Za-z0-9]{30}\b`)
)

const (
	maxAccessIDLen = 25 // 4 (LTAI) + up to 21 alphanumeric chars
	maxSecretLen   = 30

	// maxDistance is the maximum character radius between the ID and the Secret
	maxDistance = 200
)

// NewDetector returns a new Veles Detector that finds Alibaba Cloud Access Keys
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxAccessIDLen, maxSecretLen),
		MaxDistance:   uint32(maxDistance),
		FindA:         pair.FindAllMatches(accessIDPattern),
		FindB:         pair.FindAllMatches(secretPattern),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			// The framework natively enforces that the ID and Secret are found
			// within a 200-character radius of each other.
			return Credentials{AccessID: string(p.A.Value), Secret: string(p.B.Value)}, true
		},
	}
}
