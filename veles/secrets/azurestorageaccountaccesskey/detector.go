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
// Azure Storage account access keys are made by 88 characters
// They contain only base64 data ending with '=='
var keyRe = regexp.MustCompile(`[>'=?#]?[A-Za-z0-9\/+]{86}==`)

// NewDetector returns a new simpletoken.Detector that matches Azure Storage Acccount Access Key
// and returns the appropriate key type.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) veles.Secret {
			return AzureStorageAccountAccessKey{Key: string(b)}
		},
	}
}
