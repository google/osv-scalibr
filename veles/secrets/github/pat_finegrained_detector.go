// Copyright 2025 Google LLC
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

package github

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

const fineGrainedPATBase64MaxLen = 125 // 92 bytes, base64 encoded

var fineGrainedPATPattern = regexp.MustCompile(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`)

// base64(github_pat_ -> Z2l0aHViX3BhdF (minus the last incomplete byte)
var fineGrainedPATBase64Pattern = regexp.MustCompile(`Z2l0aHViX3BhdF[0-9a-zA-Z+/=]{0,111}`)

// NewFineGrainedPATDetector returns a new Veles Detector that finds Github fine-grained personal access tokens
func NewFineGrainedPATDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen:   fineGrainedPATBase64MaxLen,
		Re:       fineGrainedPATPattern,
		ReBase64: fineGrainedPATBase64Pattern,
		FromMatch: func(match []byte) (veles.Secret, bool) {
			return FineGrainedPersonalAccessToken{Token: string(match)}, true
		},
	}
}
