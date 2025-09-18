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

package tinkkeyset

import (
	"bytes"
	"encoding/base64"
	"regexp"

	"github.com/google/osv-scalibr/veles"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var (

	// base64Pattern is a generic pattern to detect base64 blobs
	base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{20,}=?=?`)

	// jsonPattern matches correctly Tink keyset json strings
	// thanks to the known `{"primaryKeyId":` start and `]}` ending
	jsonPattern = regexp.MustCompile(`(?s)\s*\{\s*"primaryKeyId"\s*:\s*\d+,\s*"key"\s*:\s*\[\s*.*?\]\s*\}`)

	// tinkTypeURL can be found in both binary and json tink keyset encodings
	tinkTypeURL = []byte("type.googleapis.com/google.crypto.tink")

	// minBase64Len is an estimate to reduce the number of blobs to decode
	// note that: len(base64(tinkTypeUrl)) is roughly 50 chars
	minBase64Len = 60
)

// Detector is a Veles Detector that finds Tink plaintext keysets.
type Detector struct{}

// NewDetector returns a new Veles Detector that finds Tink plain text keysets
func NewDetector() veles.Detector {
	return &Detector{}
}

// MaxSecretLen returns a conservative upper bound for the size of a secret in bytes.
// An exact number cannot be returned because Tink keysets may have arbitrary lengths,
func (d *Detector) MaxSecretLen() uint32 {
	return 128 * 1 << 10 // 128 KiB
}

// Detect finds Tink plain text keysets in the given data
func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	res := []veles.Secret{}
	pos := []int{}

	// search for secrets inside base64 blobs
	for _, m := range base64Pattern.FindAllIndex(data, -1) {
		l, r := m[0], m[1]
		if (r - l) < minBase64Len {
			continue
		}

		decoded := make([]byte, base64.StdEncoding.DecodedLen(r-l))
		n, err := base64.StdEncoding.Decode(decoded, data[l:r])
		if err != nil || !bytes.Contains(decoded[:n], tinkTypeURL) {
			continue
		}

		b64Found, _ := find(decoded[:n])
		// use the start of the base
		for _, found := range b64Found {
			res = append(res, found)
			pos = append(pos, l)
		}
	}

	// search for plain secrets
	if !bytes.Contains(data, tinkTypeURL) {
		return res, nil
	}

	plainFound, plainPos := find(data)
	res = append(res, plainFound...)
	pos = append(pos, plainPos...)

	return res, pos
}

func find(buf []byte) ([]veles.Secret, []int) {
	res, pos := findJSON(buf)
	if len(res) != 0 {
		return res, pos
	}
	return findBinary(buf)
}

// findBinary extract at most one binary encoded Tink keyset inside the provided buffer
//
// this function works only if the input is exactly a binary encoded Tink keyset
func findBinary(buf []byte) ([]veles.Secret, []int) {
	hnd, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(buf)))
	if err != nil {
		return nil, nil
	}
	// Valid binary keyset found, convert it to a JSON string for consistent output.
	bufOut := new(bytes.Buffer)
	if err := insecurecleartextkeyset.Write(hnd, keyset.NewJSONWriter(bufOut)); err != nil {
		return nil, nil
	}
	return []veles.Secret{TinkKeySet{Content: bufOut.String()}}, []int{0}
}

// findJSON searches for json encoded Tink keyset and extracts them
func findJSON(buf []byte) ([]veles.Secret, []int) {
	res := []veles.Secret{}
	pos := []int{}
	cleaned := clean(buf)
	for _, m := range jsonPattern.FindAllIndex(cleaned, -1) {
		l, r := m[0], m[1]
		jsonBuf := cleaned[l:r]
		hnd, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewBuffer(jsonBuf)))
		if err != nil {
			continue
		}
		// Valid keyset found, convert it back to a canonical JSON string for consistent output.
		bufOut := new(bytes.Buffer)
		if err := insecurecleartextkeyset.Write(hnd, keyset.NewJSONWriter(bufOut)); err != nil {
			return nil, nil
		}
		res = append(res, TinkKeySet{Content: bufOut.String()})
		pos = append(pos, l)
	}
	return res, pos
}

// clean removes all levels of escaping from a given buffer by eliminating every backslash character.
//
// This function is designed specifically for this detector's purpose and
// should not be used if your output is expected to contain backslashes
func clean(s []byte) []byte {
	if len(s) == 0 {
		return s
	}
	var b bytes.Buffer
	skip := false
	for i := range len(s) - 1 {
		if skip {
			skip = false
			continue
		}
		c := s[i]
		if c == '\\' {
			if s[i+1] == 'n' {
				b.WriteByte('\n')
				skip = true
			}
			continue
		}
		b.WriteByte(c)
	}
	if !skip && s[len(s)-1] != '\\' {
		b.WriteByte(s[len(s)-1])
	}
	return b.Bytes()
}
