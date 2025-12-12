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
	"encoding/base64"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

var (
	// List of special regex characters (all other chars just match themselves).
	specialChars = []string{".", "+", "*", "?", "^", "$", "(", ")", "[", "]", "{", "}", "|"}
)

// Detector finds instances of a simple token that matches the regular
// expression Re inside a chunk of text.
// It implements veles.Detector.
type Detector struct {
	// The maximum length of the token.
	MaxLen uint32
	// Matches on the token.
	Re *regexp.Regexp
	// Matches base64 encoded tokens. If present, matching blobs are decoded and
	// (if successful) are matched against the plaintext regexp.
	ReBase64 *regexp.Regexp
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
	secrets, positions = d.detectPlaintext(data)

	if d.ReBase64 != nil {
		for _, m := range d.ReBase64.FindAllIndex(data, -1) {
			buf := data[m[0]:m[1]]
			dec := make([]byte, base64.StdEncoding.DecodedLen(len(buf)))
			if _, err := base64.StdEncoding.Decode(dec, buf); err == nil {
				s, p := d.detectPlaintext(dec)
				// Adjust positions to be relative to the beginning of |data|.
				for i := range p {
					p[i] = m[0]
				}
				secrets = append(secrets, s...)
				positions = append(positions, p...)
			}
		}
	}

	return secrets, positions
}

func (d Detector) detectPlaintext(data []byte) (secrets []veles.Secret, positions []int) {
	for _, m := range d.Re.FindAllIndex(data, -1) {
		l, r := m[0], m[1]
		if match, ok := d.FromMatch(data[l:r]); ok {
			secrets = append(secrets, match)
			positions = append(positions, l)
		}
	}
	return secrets, positions
}

// ToBase64Len calculates the the max length of a base64 encoded token of the given length.
func ToBase64Len(decodedLen uint32) uint32 {
	// Base64 stores 6 bits per char and might have 2 padding bytes at the end.
	return (decodedLen*8)/6 + 3 // Add 3 instead of 2 to round up
}

// ToBase64Regexp returns a regexp pattern matching the base64 encoded version
// of the given plaintext regexp pattern.
func ToBase64Regexp(pattern string) string {
	// Compute the longest prefix of non-special chars.
	var prefixBuilder strings.Builder
	escaping := false
	for _, c := range pattern {
		c := string(c)
		if !escaping && slices.Contains(specialChars, c) {
			break
		}
		if escaping {
			escaping = false
		} else if c == "\\" {
			escaping = true
			continue // Don't store the escape character.
		}
		prefixBuilder.WriteString(c)
	}
	prefix := prefixBuilder.String()

	b64Prefix := make([]byte, base64.StdEncoding.EncodedLen(len(prefix)))
	base64.StdEncoding.Encode(b64Prefix, []byte(prefix))
	// Keep only the bytes that encode a whole 6-bit segment.
	b64Prefix = b64Prefix[:(len(prefix)*8)/6]

	// Match for base64 blobs starting with the encoded prefix.
	return string(b64Prefix) + "[0-9a-zA-Z+/=]+"
}
