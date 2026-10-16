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

package vdi

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type recordingSparseWriter struct {
	offset    int64
	size      int64
	written   int64
	seeked    int64
	truncated int64
}

func (w *recordingSparseWriter) Write(p []byte) (int, error) {
	w.written += int64(len(p))
	w.offset += int64(len(p))
	w.size = max(w.size, w.offset)
	return len(p), nil
}

func (w *recordingSparseWriter) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		w.offset = offset
	case io.SeekCurrent:
		w.offset += offset
		w.seeked += offset
	case io.SeekEnd:
		w.offset = w.size + offset
	}
	return w.offset, nil
}

func (w *recordingSparseWriter) Truncate(size int64) error {
	w.size = size
	w.truncated = size
	return nil
}

func TestConvertVDIToRawDoesNotWriteUnallocatedBlocks(t *testing.T) {
	const logicalSize = 256 << 20

	hdr := header{
		Signature:     Signature,
		Version:       0x00010001,
		ImageType:     1,
		SectorSize:    512,
		DiskSize:      logicalSize,
		BlockSize:     logicalSize,
		BlocksInImage: 1,
	}
	hdr.OffsetBmap = uint32(binary.Size(hdr))
	hdr.OffsetData = hdr.OffsetBmap + 4

	var input bytes.Buffer
	if err := binary.Write(&input, binary.LittleEndian, &hdr); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&input, binary.LittleEndian, uint32(0xffffffff)); err != nil {
		t.Fatal(err)
	}

	out := &recordingSparseWriter{}
	if err := convertVDIToRaw(&input, out); err != nil {
		t.Fatalf("convertVDIToRaw() failed: %v", err)
	}
	if out.written != 0 {
		t.Errorf("convertVDIToRaw() physically wrote %d bytes for an unallocated block, want 0", out.written)
	}
	if out.seeked != logicalSize {
		t.Errorf("convertVDIToRaw() sparse seek = %d, want %d", out.seeked, logicalSize)
	}
	if out.truncated != logicalSize {
		t.Errorf("convertVDIToRaw() output size = %d, want %d", out.truncated, logicalSize)
	}
}
