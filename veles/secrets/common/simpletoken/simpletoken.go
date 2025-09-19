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

// Package simpletoken contains a Detector for tokens that can be extracted by
// scanning a byte array with a regular expression.
package simpletoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// Detector finds instances of a simple token that matches the regular
// expression Re inside a chunk of text.
// It implements veles.Detector.
type Detector struct {
	// The maximum length of the token.
	MaxLen uint32
	// Matches on the token.
	Re *regexp.Regexp
	// Returns a veles.Secret from a regexp match.
	//  It returns the secret and a boolean indicating success.
	FromMatch func([]byte) (veles.Secret, bool)
}

// MaxSecretLen returns the maximum length of the token.
func (d Detector) MaxSecretLen() uint32 {
	return d.MaxLen
}

// Detect finds candidate tokens that match Detector.Re and returns them
// alongside their starting positions.
func (d Detector) Detect(data []byte) (secrets []veles.Secret, positions []int) {
	for _, m := range d.Re.FindAllIndex(data, -1) {
		l, r := m[0], m[1]
		if match, ok := d.FromMatch(data[l:r]); ok {
			secrets = append(secrets, match)
			positions = append(positions, l)
		}
	}
	return secrets, positions
}
