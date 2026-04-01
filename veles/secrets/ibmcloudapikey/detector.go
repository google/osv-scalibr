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

package ibmcloudapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxTokenLength is the maximum length of a valid IBM Cloud API key.
	// IBM Cloud API keys are 44 characters of mixed-case alphanumeric plus hyphen and underscore.
	maxTokenLength = 44

	// maxDistance is the maximum distance between an IBM Cloud API key and IBM keyword
	// to be considered for pairing. We look for nearby keywords to reduce false positives
	// since IBM Cloud API keys have no distinctive prefix.
	maxDistance = 200
)

var (
	// tokenRe matches IBM Cloud API key format: exactly 44 characters of [A-Za-z0-9_-].
	tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{44})\b`)

	// keywordRe matches IBM-related keywords that provide context for the key.
	// Word boundaries are omitted to match "ibm" inside compound identifiers
	// like IBM_API_KEY or ibm_cloud.
	keywordRe = regexp.MustCompile(`(?i)(ibm|bluemix|softlayer)`)
)

// NewDetector returns a detector that finds IBM Cloud API keys by pairing
// 44-character tokens with nearby IBM-related keywords.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxTokenLength, MaxDistance: maxDistance,
		FindA: pair.FindAllMatches(tokenRe),
		FindB: pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return Secret{Key: string(p.A.Value)}, true
		},
	}
}
