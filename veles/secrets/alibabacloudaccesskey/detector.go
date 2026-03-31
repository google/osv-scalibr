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

package alibabacloudaccesskey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

var (
	// accessKeyIDPattern matches Alibaba Cloud Access Key IDs which always start with LTAI
	// followed by 17 to 21 alphanumeric characters.
	// ref: https://www.alibabacloud.com/help/en/ram/user-guide/create-an-accesskey-pair
	accessKeyIDPattern = regexp.MustCompile(`\bLTAI[a-zA-Z0-9]{17,21}\b`)

	// accessKeySecretPattern matches Alibaba Cloud Access Key Secrets which are exactly
	// 30 alphanumeric characters.
	accessKeySecretPattern = regexp.MustCompile(`\b[a-zA-Z0-9]{30}\b`)
)

const (
	maxAccessKeyIDLen = 25 // LTAI + 21 chars
	maxSecretLen      = 30
	// maxDistance is the maximum distance between AccessKeyID and secrets to be considered for pairing.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// NewDetector returns a new Veles Detector that finds Alibaba Cloud Access Key pairs.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxAccessKeyIDLen, maxSecretLen),
		MaxDistance:   uint32(maxDistance),
		FindA:         pair.FindAllMatches(accessKeyIDPattern),
		FindB:         pair.FindAllMatches(accessKeySecretPattern),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return Credentials{
				AccessKeyID:     string(p.A.Value),
				AccessKeySecret: string(p.B.Value),
			}, true
		},
	}
}
