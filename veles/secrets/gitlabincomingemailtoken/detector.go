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

package gitlabincomingemailtoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructor satisfies the interface at compile time.
	_ veles.Detector = NewDetector()
)

const (
	tokenMaxLen = 50 // glimt- (6) + ~26 chars + padding
)

// tokenRe matches GitLab Incoming Email Tokens in the format:
// glimt-[a-z0-9]{25,26}
// Based on observed format: 25-26 lowercase alphanumeric characters after prefix
var tokenRe = regexp.MustCompile(`glimt-[a-z0-9]{25,26}`)

// NewDetector returns a new Detector that matches GitLab Incoming Email Tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: tokenMaxLen,
		Re:     tokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return GitlabIncomingEmailToken{Token: string(b)}, true
		},
	}
}
