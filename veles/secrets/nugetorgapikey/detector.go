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

// Package nugetorgapikey contains a Veles Secret type and a Detector for
// NuGet.org API Keys (prefix `oy2`).
package nugetorgapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a NuGet.org API key.
const maxTokenLength = 46

// keyRe is a regular expression that matches a NuGet.org API key.
// NuGet.org API keys have the form: `oy2` followed by 43
// lowercase alphanumeric characters.
var keyRe = regexp.MustCompile(`oy2[a-z0-9]{43}`)

// NewDetector returns a new simpletoken.Detector that matches
// NuGet.org API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return NuGetOrgAPIKey{Key: string(b)}, true
		},
	}
}
