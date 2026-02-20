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

package ibmclouduserkey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxTokenLength is the maximum length of a valid IBM Cloud API User key.
	// it consists of 44 chars including lower and upper case alphanumeric characters plus hyphen and underscore.
	maxTokenLength = 44

	// maxDistance is the maximum distance between IBM Cloud API User key and IBM keyword to be considered for pairing (repurposed for finding close keywords that might show it is a IBM Cloud API User key).
	// 20 is a good upper bound as we want to search for near keywords.
	maxDistance = 20
)

var (
	// tokenRe is a regular expression that matches IBM Cloud API User key.
	tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{44})\b`)

	// keywordRe is a regular expression that matches IBM related keywords.
	keywordRe = regexp.MustCompile(`(?i)(ibm)`)
)

// NewDetector returns a detector that matches IBM keyword, and an IBM Cloud API User secret.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxTokenLength, MaxDistance: maxDistance,
		FindA: pair.FindAllMatches(tokenRe),
		FindB: pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return IBMCloudUserSecret{Key: string(p.A.Value)}, true
		},
	}
}
