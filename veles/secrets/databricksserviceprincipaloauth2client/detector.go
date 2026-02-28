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

package databricksserviceprincipaloauth2client

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	// maxIDLength is the maximum length of a valid client ID.
	// There is not documented length.
	// A real demonstration from youtube suggests that it's 36.
	// For reference:
	// https://youtu.be/4wFygEnkUZw?t=271&si=HOwcCVSWh2PxtPjg
	maxIDLength = 36

	// maxSecretLength is the maximum length of a valid client secret.
	// There is not documented length.
	// A real demonstration from youtube suggests that it's 36.
	// For reference:
	// https://youtu.be/4wFygEnkUZw?t=271&si=HOwcCVSWh2PxtPjg
	maxSecretLength = 36

	// maxURLLength is the maximum length of a valid Databricks Service Principal Workspace URL.
	// There is not documented length but 100 is a good upper bound.
	maxURLLength = 100

	// maxDistance is the maximum distance between Service Principal Client IDs, Secrects, and IDs to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	// clientIDRe is a regular expression that matches Databricks Service Principal OAuth2 Client IDs.
	// A real word demonstration on youtube suggests its an UUID-like string:
	// https://youtu.be/4wFygEnkUZw?t=271&si=HOwcCVSWh2PxtPjg
	// Since it's an UUID-like string, it is possible that hypens are not present in the string (edge case).
	// Therefore, I have chosen 32 as the minimum length.
	clientIDRe = regexp.MustCompile(`(?i)\bclient[_-]?id\b\s*[:=]?\s*([A-Za-z0-9\-]{32,36})\b`)

	// clientSecretRe is a regular expression that matches Databricks Service Principal OAuth2 Client Secrets.
	// A real word demonstration on youtube suggests it starts with "dose" prefix followed by an alphanumeric string:
	// https://youtu.be/4wFygEnkUZw?t=271&si=HOwcCVSWh2PxtPjg
	clientSecretRe = regexp.MustCompile(`\bdose[A-Za-z0-9._\-]{32}\b`)

	// workspaceURLRe is a regular expression that matches Databricks Service Principal Workspace URL.
	// References:
	// https://docs.databricks.com/aws/en/workspace/workspace-details
	// https://docs.databricks.com/gcp/en/workspace/workspace-details
	// https://learn.microsoft.com/en-us/azure/databricks/workspace/workspace-details
	workspaceURLRe = regexp.MustCompile(
		`\b(?:` +
			// Azure
			`adb-[a-zA-Z0-9-]+\.[0-9]+\.azuredatabricks\.net` +
			`|` +
			// AWS + GCP
			`(?:db-sme-[a-zA-Z0-9-]+|[a-zA-Z0-9-]+\.[0-9]+)\.(?:cloud|gcp)\.databricks\.com(?:\?o=[a-zA-Z0-9-]+)?` +
			`)\b`,
	)
)

// NewDetector returns a detector that matches Databricks Service Principal OAuth2 Client Credentials.
func NewDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxIDLength, maxSecretLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatchesGroup(workspaceURLRe),
			ntuple.FindAllMatches(clientSecretRe),
			ntuple.FindAllMatchesGroup(clientIDRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return Credentials{URL: string(ms[0].Value), Secret: string(ms[1].Value), ID: string(ms[2].Value)}, true
		},
	}
}
