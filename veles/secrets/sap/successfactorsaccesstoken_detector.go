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

package sap

import (
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

// NewSAPSuccessFactorsAccessTokenDetector returns a detector that matches SAP Success Factors Credentials.
func NewSAPSuccessFactorsAccessTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: maxAccessTokenLength,
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatchesGroup(accessTokenRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return SuccessFactorsAccessToken{Token: string(ms[0].Value)}, true
		},
	}
}
