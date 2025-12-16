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

package bitbucket

import (
	"net/url"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth"
)

const (
	// maxURLLength is an upper bound value for the length of a URL to be considered.
	// This helps limit the buffer size required for scanning.
	maxURLLength = 1_000
)

var (
	// urlPattern matches URLs containing basic authentication credentials.
	urlPattern = regexp.MustCompile(`\bhttps://[^:\s]+:[^\s@]+@bitbucket\.org/[^\s]+\.git\b`)
)

// NewDetector creates and returns a new instance of the Bitbucket secret detector.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxURLLength,
		Re:     urlPattern,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			u, err := url.Parse(string(b))
			if err != nil {
				return nil, false
			}
			if !gitbasicauth.HasValidCredentials(u) {
				return nil, false
			}
			return Credentials{FullURL: u.String()}, true
		},
	}
}
