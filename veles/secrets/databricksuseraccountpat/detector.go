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

package databricksuseraccountpat

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	// maxTokenLength is the maximum length of a valid Databricks User Account Personal Access Token.
	// There is no documented length.
	// An official example suggests it's 36 characters in length:
	// Reference: https://docs.databricks.com/api/gcp/workspace/tokenmanagement/createobotoken
	// However, real word demonstrations from youtube suggest that it's somewhere between 36 to 40:
	// Length 36: https://youtu.be/yyy7LA4H4co?t=682&si=lS0VuWNJ8ciPh9OC
	// Length 38: https://youtube.com/shorts/nM-2L-taB1M?si=CTwdfH17xm-ySsG_
	// Length 38: https://youtu.be/4wFygEnkUZw?t=186&si=aMrAjSBN4-xGBjJO
	// Therefore, 38 is a good upper bound.
	maxTokenLength = 38

	// maxAccountIDLength is the maximum length of a valid Databricks User Account ID.
	// There is not documented length but we can guess it from the following official demonstration:
	// https://docs.databricks.com/aws/en/admin/account-settings#account-id
	maxAccountIDLength = 35

	// maxDistance is the maximum distance between User Account PATs and IDS to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	// tokenRe is a regular expression that matches Databricks User Account Personal Access Token.
	// Reference: https://docs.databricks.com/api/gcp/workspace/tokenmanagement/createobotoken
	// Moreover, here are few real word demonstrations on youtube:
	// https://youtu.be/yyy7LA4H4co?t=682&si=lS0VuWNJ8ciPh9OC
	// https://youtube.com/shorts/nM-2L-taB1M?si=CTwdfH17xm-ySsG_
	// https://youtu.be/4wFygEnkUZw?t=186&si=aMrAjSBN4-xGBjJO
	tokenRe = regexp.MustCompile(`\bdapi[A-Za-z0-9._\-]{32,34}\b`)

	// accountIDRe is a regular expression that matches Databricks User Account ID.
	// Reference: https://docs.databricks.com/aws/en/admin/account-settings#account-id
	accountIDRe = regexp.MustCompile(`(?i)\baccount[_-]?id\b\s*[:=]?\s*([A-Za-z0-9\-]{35})\b`)
)

// NewDetector returns a detector that matches Databricks User Account Personal Access Token Credentials.
func NewDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxTokenLength, maxAccountIDLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(tokenRe),
			ntuple.FindAllMatchesGroup(accountIDRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return Credentials{Token: string(ms[0].Value), AccountID: string(ms[1].Value)}, true
		},
	}
}
