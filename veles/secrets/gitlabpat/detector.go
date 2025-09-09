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

// Package gitlabpat contains a Veles Secret type and a Detector for
// Gitlab Personal Access Tokens (prefix `glpat-`).
package gitlabpat

import (
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// maxTokenLength is the maximum size of a Gitlab personal access token.
const maxTokenLength = 57

// patRe is a regular expression that matches a Gitlab PAT.
// Gitlab PAT has the form: `glpat-` followed by 51 alphanumeric characters.
var patRe = regexp.MustCompile(`glpat-[A-Za-z0-9._-]{51}`)

var _ veles.Detector = NewDetector()

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a new Detector that matches
// Gitlab Personal Access Tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxTokenLength
}
func (d *detector) Detect(content []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var offsets []int

	matches := patRe.FindAll(content, -1)
	for _, match := range matches {
		secrets = append(secrets, GitlabPat{Pat: string(match)})
		offsets = append(offsets, bytes.Index(content, match))
	}
	return secrets, offsets
}
