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

// Package checksum contains the checksum validation logic for github tokens
package checksum

import (
	"bytes"
	"hash/crc32"
)

// Validate validates a GitHub token
func Validate(token []byte) bool {
	_, suf, ok := bytes.Cut(token, []byte("_"))
	if !ok {
		return false
	}

	if len(suf) <= 6 {
		return false
	}

	// Split content and checksum
	splitIdx := len(suf) - 6
	content, checksum := suf[:splitIdx], suf[splitIdx:]

	// Compute CRC32 on ASCII bytes of the content (not decoded base62)
	crc := crc32.ChecksumIEEE(content)

	// Encode checksum in base62 (ignoring a possible overflow)
	got := base62Encode(crc, 6)

	return bytes.Equal(got, checksum)
}

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func base62Encode(n uint32, size int) []byte {
	result := make([]byte, size)
	for i := size - 1; i >= 0; i-- {
		result[i] = base62Chars[n%62]
		n /= 62
	}
	// ignore the overflow
	return result
}
