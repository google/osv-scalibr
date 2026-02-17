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

package nugetapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructor satisfies the interface at compile time.
	_ veles.Detector = NewDetector()
)

// NuGet API Key structure:
// Pattern: Starts with "oy2" followed by 43 lowercase alphanumeric characters (a-z, 0-9).
// Total length: 46 characters.
const nugetMaxLen = 46

var nugetRe = regexp.MustCompile(`oy2[a-z0-9]{43}`)

// NewDetector returns a detector for NuGet.org API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: nugetMaxLen,
		Re:     nugetRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return NuGetAPIKey{Key: string(b)}, true
		},
	}
}
