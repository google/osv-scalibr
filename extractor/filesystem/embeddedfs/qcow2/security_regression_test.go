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
	"encoding/binary"
	"os"
	"runtime"
	"testing"
)

// craftMaliciousQCOW2ExtLength builds a 120-byte QCOW2 whose header passes
// all bounds guards (ClusterBits=12, L1Size=1, RefcountTableClusters=1) but
// contains a header extension with Length=0xffffffff (~4 GB).
// Without the fix, make([]byte, ext.Length) allocates ~4 GB before the
// subsequent io.ReadFull returns EOF.
func craftMaliciousQCOW2ExtLength(t *testing.T) string {
	t.Helper()

	hdr := make([]byte, 112)
	be := binary.BigEndian
	be.PutUint32(hdr[0:], 0x514649FB) // Magic
	be.PutUint32(hdr[4:], 3)          // Version 3
	be.PutUint32(hdr[20:], 12)        // ClusterBits = 12 (valid: within [9,21])
	be.PutUint64(hdr[24:], 1<<12)     // Size
	be.PutUint32(hdr[32:], 0)         // CryptMethod = 0
	be.PutUint32(hdr[36:], 1)         // L1Size = 1 (valid)
	be.PutUint32(hdr[56:], 1)         // RefcountTableClusters = 1 (valid)
	be.PutUint32(hdr[100:], 112)      // HeaderLength = 112

	// Extension with non-zero Type and Length = 0xffffffff (~4 GB).
	ext := make([]byte, 8)
	be.PutUint32(ext[0:], 0xdeadbeef) // ext.Type (non-zero: loop continues)
	be.PutUint32(ext[4:], 0xffffffff) // ext.Length → make([]byte, ~4 GB)

	f, err := os.CreateTemp(t.TempDir(), "scalibr-qcow2-extlength-*.qcow2")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	for _, b := range [][]byte{hdr, ext} {
		if _, err := f.Write(b); err != nil {
			f.Close()
			t.Fatalf("Write: %v", err)
		}
	}
	f.Close()
	return f.Name()
}

// TestConvertQCOW2ExtLengthRejected verifies that a crafted QCOW2 header
// extension with Length=0xffffffff is rejected before any large allocation.
// Without the fix, a 120-byte input causes a ~4 GB heap allocation
// (TotalAlloc delta confirmed at 4096 MB live before the patch).
func TestConvertQCOW2ExtLengthRejected(t *testing.T) {
	inputPath := craftMaliciousQCOW2ExtLength(t)

	outFile, err := os.CreateTemp(t.TempDir(), "scalibr-qcow2-out-*.raw")
	if err != nil {
		t.Fatalf("CreateTemp output: %v", err)
	}
	outFile.Close()
	outputPath := outFile.Name()

	t.Logf("Malicious QCOW2 ext.Length bomb: 120 bytes on disk")
	t.Logf("ext.Length = 0xffffffff => make([]byte, 4294967295) = ~4 GB attempted without fix")

	var msBefore, msAfter runtime.MemStats
	runtime.ReadMemStats(&msBefore)

	convertErr := convertQCOW2ToRaw(inputPath, outputPath, "")

	runtime.ReadMemStats(&msAfter)
	allocMB := (msAfter.TotalAlloc - msBefore.TotalAlloc) >> 20

	t.Logf("convertQCOW2ToRaw err: %v", convertErr)
	t.Logf("TotalAlloc delta: %d MB", allocMB)

	if convertErr == nil {
		t.Errorf("expected error for malicious ext.Length=0xffffffff, got nil")
	}
	if allocMB > 50 {
		t.Errorf("TotalAlloc delta %d MB exceeds 50 MB — ext.Length bounds check missing or ineffective", allocMB)
	}
}
