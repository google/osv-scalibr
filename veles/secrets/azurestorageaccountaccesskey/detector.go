// Copyright 2025 Google LLC
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
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// Azure Storage Account Access Key maximum length is 88 chars.
const maxTokenLength = 88

// keyRe is a regular expression that matches an azure storage account access keys.
// Azure Storage account access keys are made by:
// - zero to one of the greater than symbol (>), apostrophe ('), equal sign (=), quotation mark ("), or number sign (#)
// - a combination of 86 characters that are lower- or uppercase letters, digits, the forward slash (/), or plus sign (+)
// - two equal signs (=)
//
// References:
// - https://learn.microsoft.com/en-us/purview/sit-defn-azure-storage-account-key-generic
var keyRe = regexp.MustCompile(`(?i)(?:(?:AZURE|ACCOUNT|STORAGE|ACCESS)[_.-]?){1,4}KEY.{0,5}?([>'=?#]?[A-Za-z0-9+\/]{86}==)`)

// NewDetector returns a new simpletoken.Detector
// that matches Azure Storage Account Access Key and returns the appropriate key type.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			// Extract the capture group (the actual key)
			matches := keyRe.FindSubmatch(b)
			// In the regex we have the following matches:
			// 1st is the entire string
			// 2nd is the key
			if len(matches) != 2 {
				return nil, false
			}
			return AzureStorageAccountAccessKey{Key: string(matches[1])}, true
		},
	}
}
