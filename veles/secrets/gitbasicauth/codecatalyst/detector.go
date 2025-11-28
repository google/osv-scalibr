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
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

const (
	maxURLLength = 1_000
)

var (
	urlPattern = regexp.MustCompile(`\bhttps://([^:\s]+):([^\s@]+)@[^/]*codecatalyst\.aws/[^\s]*`)
)

type detector struct{}

func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxURLLength
}

func (d *detector) Detect(data []byte) ([]veles.Secret, []int) {
	secrets, positions := []veles.Secret{}, []int{}
	matches := urlPattern.FindAllSubmatchIndex(data, -1)
	for _, m := range matches {
		secrets = append(secrets, Credentials{
			FullURL:  string(data[m[0]:m[1]]),
			Username: string(data[m[2]:m[3]]),
			Password: string(data[m[4]:m[5]]),
		})
	}
	return secrets, positions
}
