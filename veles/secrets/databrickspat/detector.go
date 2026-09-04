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

// Package databrickspat contains a Veles Secret type and Detector for
// Databricks User Account Personal Access Tokens (prefix `dapi`).
package databrickspat

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Databricks User Account PAT, plus
// one optional terminating delimiter consumed by patRe.
const maxTokenLength = 40

// patRe is a regular expression that matches a Databricks User Account PAT.
// Databricks API tokens have the form: `dapi` followed by 32 lowercase
// hexadecimal characters, with an optional single digit suffix.
var patRe = regexp.MustCompile(`\bdapi[a-f0-9]{32}(?:-\d)?(?:[^A-Za-z0-9-]|$)`)

// NewDetector returns a new simpletoken.Detector that matches Databricks User
// Account Personal Access Tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     patRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			if len(b) > 0 && !isHexChar(b[len(b)-1]) {
				b = b[:len(b)-1]
			}
			return UserAccountPAT{Token: string(b)}, true
		},
	}
}

func isHexChar(b byte) bool {
	return (b >= 'a' && b <= 'f') || (b >= '0' && b <= '9')
}
