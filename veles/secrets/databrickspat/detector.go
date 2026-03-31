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

package databrickspat

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	// maxTokenLength is the maximum length of a Databricks PAT.
	// Format: "dapi" prefix + 32-36 alphanumeric characters.
	// Official examples show 36-char tokens, YouTube demos show 36-38.
	// Reference: https://docs.databricks.com/api/gcp/workspace/tokenmanagement/createobotoken
	maxTokenLength = 40

	// maxURLLength is the maximum length of a Databricks Workspace URL.
	maxURLLength = 100

	// maxDistance is the maximum byte distance between the token and URL
	// to be considered a pair. 10 KiB covers most config files.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	// tokenRe matches Databricks Personal Access Tokens.
	// Format: "dapi" prefix followed by 32-36 alphanumeric characters.
	// Reference: https://docs.databricks.com/api/gcp/workspace/tokenmanagement/createobotoken
	tokenRe = regexp.MustCompile(`\bdapi[a-zA-Z0-9]{32,36}\b`)

	// workspaceURLRe matches Databricks Workspace URLs across all cloud providers:
	//   - AWS: *.cloud.databricks.com
	//   - GCP: *.gcp.databricks.com
	//   - Azure: *.azuredatabricks.net
	workspaceURLRe = regexp.MustCompile(`\b[a-zA-Z0-9][a-zA-Z0-9._-]+(?:\.(?:cloud|gcp)\.databricks\.com|\.azuredatabricks\.net)\b`)
)

// NewDetector returns a detector that matches Databricks PAT credentials
// by pairing a "dapi"-prefixed token with a nearby workspace URL.
func NewDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxTokenLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(tokenRe),
			ntuple.FindAllMatches(workspaceURLRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return PATCredentials{
				Token: string(ms[0].Value),
				URL:   string(ms[1].Value),
			}, true
		},
	}
}
