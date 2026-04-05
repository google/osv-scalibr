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

// Package databrickspat contains a Veles Secret type and a Detector for
// Databricks Personal Access Tokens (prefix `dapi`).
package databrickspat

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Databricks Personal Access Token.
// Databricks PATs have the form: `dapi` (4 chars) + 32 hex characters = 36 chars.
const maxTokenLength = 36

// tokenRe is a regular expression that matches a Databricks Personal Access Token.
// Databricks PATs have the form: `dapi` followed by 32 lowercase hexadecimal characters.
var tokenRe = regexp.MustCompile(`dapi[a-f0-9]{32}`)

// NewDetector returns a new simpletoken.Detector that matches
// Databricks Personal Access Tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     tokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return DatabricksPAT{Token: string(b)}, true
		},
	}
}
