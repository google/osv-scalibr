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

package databricks

import (
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

// NewUAOAuth2ClientDetector returns a detector that matches Databricks User Account OAuth2 Client Credentials.
func NewUAOAuth2ClientDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxIDLength, maxSecretLength, maxAccountIDLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatchesGroup(clientIDRe),
			ntuple.FindAllMatches(clientSecretRe),
			ntuple.FindAllMatchesGroup(accountIDRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return UAOAuth2ClientCredentials{ID: string(ms[0].Value), Secret: string(ms[1].Value), AccountID: string(ms[2].Value)}, true
		},
	}
}
