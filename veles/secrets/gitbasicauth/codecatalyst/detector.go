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

package codecatalyst

import (
	"net/url"
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

const (
	// maxURLLength is an upper bound value for the length of a URL to be considered.
	// This helps limit the buffer size required for scanning.
	maxURLLength = 1_000
)

var (
	// urlPattern matches URLs containing basic authentication credentials.
	urlPattern = regexp.MustCompile(`\bhttps://[^:\s]+:[^\s@]+@[^/]*codecatalyst\.aws/[^\s]*`)
)

type detector struct{}

// NewDetector creates and returns a new instance of the CodeCatalyst secret detector.
func NewDetector() veles.Detector {
	return &detector{}
}

// MaxSecretLen returns the maximum expected length of the secret.
func (d *detector) MaxSecretLen() uint32 {
	return maxURLLength
}

// Detect scans the provided byte slice for AWS CodeCatalyst credentials.
func (d *detector) Detect(data []byte) ([]veles.Secret, []int) {
	secrets, positions := []veles.Secret{}, []int{}
	matches := urlPattern.FindAllSubmatchIndex(data, -1)
	for _, m := range matches {
		fullURL := data[m[0]:m[1]]
		u, err := url.Parse(string(fullURL))
		if err != nil {
			continue
		}
		if u.User == nil {
			continue
		}
		username := u.User.Username()
		if username == "" {
			continue
		}
		password, ok := u.User.Password()
		if !ok {
			continue
		}
		secrets = append(secrets, Credentials{
			FullURL:  u.String(),
			Username: username,
			PAT:      password,
		})
	}
	return secrets, positions
}
