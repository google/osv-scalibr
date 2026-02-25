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

package azurestorageaccountaccesskey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

// Azure Storage Account Access Key maximum length is 88 chars.
const (
	maxTokenLength = 88
	contextLength  = 20
	maxLen         = maxTokenLength + contextLength
)

var (
	// keyRe is a regular expression that matches an azure storage account access keys.
	// Azure Storage account access keys are made by:
	// - zero to one of the greater than symbol (>), apostrophe ('), equal sign (=), quotation mark ("), or number sign (#)
	// - a combination of 86 characters that are lower- or uppercase letters, digits, the forward slash (/), or plus sign (+)
	// - two equal signs (=)
	//
	// References:
	// - https://learn.microsoft.com/en-us/purview/sit-defn-azure-storage-account-key-generic
	keyRe = regexp.MustCompile(`(?i)KEY.{0,5}?([>'=?#]?[A-Za-z0-9+\/]{86}==)`)

	// azureRe matches azure and az
	azureRe = regexp.MustCompile(`(?i)azure|(?:\baz\b)`)
)

// NewDetector returns a new pair.Detector
// that matches Azure Storage Account Access Key and returns the appropriate key type.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxLen, MaxDistance: 100,
		FindA: findAzureStorageAccountKeys,
		FindB: pair.FindAllMatches(azureRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return AzureStorageAccountAccessKey{Key: string(p.A.Value)}, true
		},
	}
}

func findAzureStorageAccountKeys(data []byte) []*pair.Match {
	matches := keyRe.FindAllSubmatchIndex(data, -1)
	var results []*pair.Match
	for _, m := range matches {
		results = append(results, &pair.Match{
			Start: m[0],
			Value: data[m[2]:m[3]],
		})
	}
	return results
}
