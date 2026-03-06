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
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

var (
	// workspaceSPPATURLRe is a regular expression that matches Databricks Service Principal Workspace URL.
	// Reference: https://docs.databricks.com/aws/en/admin/account-settings#account-id
	workspaceSPPATURLRe = regexp.MustCompile(`\b[a-zA-Z0-9._\-]+(?:\.(?:cloud|gcp)\.databricks\.com|\.azuredatabricks\.net)\b`)
)

// NewSPPATDetector returns a detector that matches Databricks Service Principal Personal Access Token Credentials.
func NewSPPATDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxTokenLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(tokenRe),
			ntuple.FindAllMatches(workspaceSPPATURLRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return SPPATCredentials{Token: string(ms[0].Value), URL: string(ms[1].Value)}, true
		},
	}
}
