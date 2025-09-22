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

package gcpexpressmode

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	keyRe = regexp.MustCompile(`AQ\.Ab8R[a-zA-Z0-9_-]{46}`)
)

const (
	maxKeyLen = 53
)

// NewDetector creates a new Veles Detector that finds candidate GCP Express Mode API keys.
func NewDetector() veles.Detector {
	return &simpletoken.Detector{
		Re:     keyRe,
		MaxLen: maxKeyLen,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}
