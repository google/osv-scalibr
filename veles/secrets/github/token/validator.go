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

// Package token contains common logic to handle github tokens
package token

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

type CheckSumValidator[T GithubToken] struct{}

func NewCheckSumValidator[T GithubToken]() veles.Validator[T] {
	return CheckSumValidator[T]{}
}

// Validate validates a GitHub token
func (c CheckSumValidator[T]) Validate(ctx context.Context, key T) (veles.ValidationStatus, error) {
	if err := ctx.Err(); err != nil {
		return veles.ValidationFailed, err
	}

	t := strings.TrimSpace(key.GetToken())
	_, suf, ok := strings.Cut(t, "_")
	if !ok {
		return veles.ValidationFailed, errors.New("invalid token format")
	}

	if len(suf) <= 6 {
		return veles.ValidationFailed, errors.New("too short")
	}

	// Split content and checksum
	splitIdx := len(suf) - 6
	content, checksum := suf[:splitIdx], suf[splitIdx:]

	// Compute CRC32 on ASCII bytes of the content (not decoded base62)
	crc := crc32.ChecksumIEEE([]byte(content))

	// Encode checksum in base62 (ignoring a possible overflow)
	got := base62Encode(crc, 6)

	// Compare checksums
	if !bytes.Equal(got, []byte(checksum)) {
		return veles.ValidationFailed, fmt.Errorf("checksum mismatch: got %s, want %s", string(got), checksum)
	}

	return veles.ValidationValid, nil
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
