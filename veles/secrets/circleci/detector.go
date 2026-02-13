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

package circleci

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewPersonalAccessTokenDetector()
	_ veles.Detector = NewProjectTokenDetector()
)

const (
	patMaxLen     = 70 // CCIPAT_ (7) + identifier (22) + _ (1) + 40 hex chars = 70
	projectMaxLen = 70 // CCIPRJ_ (7) + identifier (22) + _ (1) + 40 hex chars = 70
)

// circleCIPATRe matches CircleCI Personal Access Tokens in the format:
// CCIPAT_[A-Za-z0-9]{22}_[0-9a-f]{40}
var circleCIPATRe = regexp.MustCompile(`CCIPAT_[A-Za-z0-9]{22}_[0-9a-f]{40}`)

// circleCIProjectRe matches CircleCI Project Tokens in the format:
// CCIPRJ_[A-Za-z0-9]{22}_[0-9a-f]{40}
var circleCIProjectRe = regexp.MustCompile(`CCIPRJ_[A-Za-z0-9]{22}_[0-9a-f]{40}`)

// NewPersonalAccessTokenDetector returns a detector for CircleCI Personal Access Tokens.
func NewPersonalAccessTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: patMaxLen,
		Re:     circleCIPATRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return PersonalAccessToken{Token: string(b)}, true
		},
	}
}

// NewProjectTokenDetector returns a detector for CircleCI Project Tokens.
func NewProjectTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: projectMaxLen,
		Re:     circleCIProjectRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ProjectToken{Token: string(b)}, true
		},
	}
}
