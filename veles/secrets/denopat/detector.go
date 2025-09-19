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

// Package denopat contains a Veles Secret type and a Detector for
// Deno Personal Access Tokens (prefix `ddo_` and `ddp_`).
package denopat

import (
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// maxTokenLength is the maximum size of a Deno PAT.
const maxTokenLength = 40

// patRe is a regular expression that matches a Deno Personal Access Token.
// Deno Personal Access Tokens have the form: `ddo_` and `ddp_` followed by 36
// alphanumeric characters.
var patRe = regexp.MustCompile(`(?:ddp|ddo)_[A-Za-z0-9]{36}`)

var _ veles.Detector = NewDetector()

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a new Detector that matches
// Deno PAT.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxTokenLength
}
func (d *detector) Detect(content []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var offsets []int
	patReMatches := patRe.FindAll(content, -1)
	for _, m := range patReMatches {
		newPat := string(m)
		secrets = append(secrets, DenoPAT{Pat: newPat})
		offsets = append(offsets, bytes.Index(content, m))
	}

	return secrets, offsets
}
