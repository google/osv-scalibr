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
	// workspaceSPOAuth2ClientURLRe is a regular expression that matches Databricks Service Principal Workspace URL.
	// References:
	// https://docs.databricks.com/aws/en/workspace/workspace-details
	// https://docs.databricks.com/gcp/en/workspace/workspace-details
	// https://learn.microsoft.com/en-us/azure/databricks/workspace/workspace-details
	workspaceSPOAuth2ClientURLRe = regexp.MustCompile(
		`\b(?:` +
			// Azure
			`adb-[a-zA-Z0-9-]+\.[0-9]+\.azuredatabricks\.net` +
			`|` +
			// AWS + GCP
			`(?:db-sme-[a-zA-Z0-9-]+|[a-zA-Z0-9-]+\.[0-9]+)\.(?:cloud|gcp)\.databricks\.com(?:\?o=[a-zA-Z0-9-]+)?` +
			`)\b`,
	)
)

// NewSPOAuth2ClientDetector returns a detector that matches Databricks Service Principal OAuth2 Client Credentials.
func NewSPOAuth2ClientDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxIDLength, maxSecretLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatchesGroup(workspaceSPOAuth2ClientURLRe),
			ntuple.FindAllMatches(clientSecretRe),
			ntuple.FindAllMatchesGroup(clientIDRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return SPOAuth2ClientCredentials{URL: string(ms[0].Value), Secret: string(ms[1].Value), ID: string(ms[2].Value)}, true
		},
	}
}
