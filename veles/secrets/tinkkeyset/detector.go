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

	// jsonPattern matches correctly tink keyset json strings
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

// Detect finds Tink plain text keysets in the given data
func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	res := []veles.Secret{}
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
		res = append(res, d.find(decoded[:n])...)
	}
	if !bytes.Contains(data, tinkTypeURL) {
		return res, nil
	}
	res = append(res, d.find(data)...)
	return res, nil
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

func (d *Detector) find(buf []byte) []veles.Secret {
	res := d.findJSON(buf)
	if len(res) != 0 {
		return res
	}
	return d.findBinary(buf)
}

func (d *Detector) findJSON(buf []byte) []veles.Secret {
	res := []veles.Secret{}
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
			return nil
		}
		res = append(res, TinkKeySet{Content: bufOut.String()})
	}
	return res
}

func (d *Detector) findBinary(buf []byte) []veles.Secret {
	hnd, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(buf)))
	if err != nil {
		return nil
	}
	// Valid binary keyset found, convert it to a JSON string for consistent output.
	bufOut := new(bytes.Buffer)
	if err := insecurecleartextkeyset.Write(hnd, keyset.NewJSONWriter(bufOut)); err != nil {
		return nil
	}
	return []veles.Secret{TinkKeySet{Content: bufOut.String()}}
}

// MaxSecretLen returns 0 since a secret found by this detector may contain multiple keys
func (d *Detector) MaxSecretLen() uint32 {
	return 0
}
