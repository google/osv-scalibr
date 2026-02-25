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

package qcow2

import (
	"bytes"
	"compress/flate"
	"testing"
)

func deflateRaw(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("failed to create deflate writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("failed to write deflate data: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close deflate writer: %v", err)
	}
	return buf.Bytes()
}

func TestDecompressRawDeflate_Success(t *testing.T) {
	original := []byte("this is some test data for raw deflate")
	compressed := deflateRaw(t, original)

	out, err := decompressRawDeflate(compressed, uint64(len(original)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(out, original) {
		t.Fatalf("decompressed data mismatch: got %q, want %q", out, original)
	}
}

func TestDecompressRawDeflate_ExactSize(t *testing.T) {
	original := make([]byte, 4096)
	for i := range original {
		original[i] = byte(i % 256)
	}
	compressed := deflateRaw(t, original)

	out, err := decompressRawDeflate(compressed, uint64(len(original)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out) != len(original) {
		t.Fatalf("unexpected output size: got %d, want %d", len(out), len(original))
	}
}

func TestDecompressRawDeflate_TruncatedOutput(t *testing.T) {
	original := []byte("hello world")
	compressed := deflateRaw(t, original)

	_, err := decompressRawDeflate(compressed, uint64(len(original)+10))
	if err == nil {
		t.Fatalf("expected error due to insufficient compressed data")
	}
}

func TestDecompressRawDeflate_InvalidData(t *testing.T) {
	invalid := []byte{0x00, 0x01, 0x02, 0x03}

	_, err := decompressRawDeflate(invalid, 16)
	if err == nil {
		t.Fatalf("expected error for invalid compressed input")
	}
}
