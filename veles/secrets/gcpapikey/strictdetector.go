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

package gcpapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// maxTokenLength is the maximum size of a GPC API key. Adding a buffer to the actual maximum length of 40 characters to account for potential prefixes/suffixes.
const maxTokenLengthStrict = 40

// strictRe is a regular expression that matches a GCP API key with boundary checks.
var strictRe = regexp.MustCompile(`\b(AIza[a-zA-Z0-9_-]{35})(?:[^a-zA-Z0-9_-]|$)`)

// strictDetector is a Veles Detector.
type strictDetector struct{}

// NewStrictDetector returns a new Detector that matches GCP API keys with
// boundary checks.
func NewStrictDetector() veles.Detector {
	return &strictDetector{}
}

func (d *strictDetector) MaxSecretLen() uint32 {
	return maxTokenLength
}

func (d *strictDetector) Detect(content []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int
	for _, m := range strictRe.FindAllSubmatchIndex(content, -1) {
		if len(m) != 4 {
			continue
		}
		l, r := m[2], m[3]
		key := string(content[l:r])
		secrets = append(secrets, GCPAPIKey{Key: key})
		positions = append(positions, l)
	}
	return secrets, positions
}
