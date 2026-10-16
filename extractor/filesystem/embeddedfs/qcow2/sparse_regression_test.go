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
	"io"
	"testing"
)

type recordingSparseWriter struct {
	offset  int64
	written int64
	seeked  int64
}

func (w *recordingSparseWriter) Write(p []byte) (int, error) {
	w.written += int64(len(p))
	w.offset += int64(len(p))
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
		return 0, io.ErrUnexpectedEOF
	}
	return w.offset, nil
}

func TestWriteRawImageDoesNotWriteUnallocatedClusters(t *testing.T) {
	const logicalSize = 256 << 20

	hdr := &header{
		ClusterBits: 16,
		Size:        logicalSize,
	}
	out := &recordingSparseWriter{}
	if err := writeRawImage(hdr, []uint64{0}, bytes.NewReader(nil), out, nil, 0); err != nil {
		t.Fatalf("writeRawImage() failed: %v", err)
	}
	if out.written != 0 {
		t.Errorf("writeRawImage() physically wrote %d bytes for unallocated clusters, want 0", out.written)
	}
	if out.seeked != logicalSize {
		t.Errorf("writeRawImage() sparse seek = %d, want %d", out.seeked, logicalSize)
	}
}
