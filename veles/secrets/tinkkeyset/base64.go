// Copyright 2026 Google LLC
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

package tinkkeyset

import (
	"encoding/base64"
	"math"
	"strings"
)

// Base64SubstringPattern returns a regexp pattern that matches a base64-encoded
// string containing the given plaintext.
//
// Note: base64 encodes 3-byte blocks into 4 characters, the embedded plaintext
// can have 3 possible byte alignments (shifted by 0, 1, or 2 bytes).
func Base64SubstringPattern(plaintext string) string {
	if len(plaintext) < 3 {
		panic("the plaintext is too short (minimum 2 bytes required)")
	}
	patterns := make([]string, 3)
	for i := range 3 {
		buf := make([]byte, i+len(plaintext))
		copy(buf[i:], []byte(plaintext))
		encoded := base64.StdEncoding.EncodeToString(buf)

		// start and end of the actual given plaintext, skipping the padding
		start := int(math.Ceil(float64(i*8) / 6))
		end := int(math.Floor(float64((i+len(plaintext))*8) / 6))
		patterns[i] = encoded[start:end]
	}
	return `[A-Za-z0-9+/]*(?:` + strings.Join(patterns, "|") + `)[A-Za-z0-9+/]*={0,2}`
}
