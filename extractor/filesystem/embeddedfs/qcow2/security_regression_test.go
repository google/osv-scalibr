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

// craftMaliciousQCOW2 builds a minimal 116-byte QCOW2 file whose ClusterBits
// field is set to clusterBits, causing clusterSize = 1 << clusterBits.
// The file passes all parseHeader checks and reaches readL2Table where
// make([]byte, clusterSize) is called with no bounds check.
func craftMaliciousQCOW2(t *testing.T, clusterBits uint32) string {
	t.Helper()

	// QCOW2 header is 112 bytes, big-endian.
	// Offsets match the header struct fields in format.go.
	hdr := make([]byte, 112)
	be := binary.BigEndian

	be.PutUint32(hdr[0:], 0x514649FB)      // Magic
	be.PutUint32(hdr[4:], 3)               // Version = 3
	be.PutUint32(hdr[20:], clusterBits)    // ClusterBits
	be.PutUint64(hdr[24:], 1<<clusterBits) // Size = 1 cluster (loop runs once)
	be.PutUint32(hdr[32:], 0)              // CryptMethod = 0
	be.PutUint32(hdr[36:], 1)              // L1Size = 1
	be.PutUint64(hdr[40:], 0)              // L1TableOffset = 0 (points to file start)
	be.PutUint64(hdr[48:], 0)              // RefcountTableOffset = 0
	be.PutUint32(hdr[56:], 0)              // RefcountTableClusters = 0
	be.PutUint32(hdr[100:], 112)           // HeaderLength = 112
	// CompressionType (hdr[104]) = 0
	// IncompatibleFeatures (hdr[72:80]) = 0

	// 4-byte extension end marker terminates the extension loop.
	payload := make([]byte, len(hdr)+4)
	copy(payload, hdr)

	f, err := os.CreateTemp(t.TempDir(), "scalibr-qcow2-bomb-*.qcow2")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		t.Fatalf("Write: %v", err)
	}
	f.Close()
	return f.Name()
}

// TestConvertQCOW2ClusterBitsRejected is the security regression test.
// A crafted QCOW2 with ClusterBits=33 (8 GB cluster) must be rejected
// immediately with 0 MB TotalAlloc delta.
// Without the fix, clusterSize = 1<<33 = 8 GB is passed to make() inside
// readL2Table with no bounds check, causing an 8 GB heap allocation from a
// 116-byte input file (confirmed live: "runtime: out of memory").
func TestConvertQCOW2ClusterBitsRejected(t *testing.T) {
	const clusterBits = 33 // 1<<33 = 8 GB

	inputPath := craftMaliciousQCOW2(t, clusterBits)

	outFile, err := os.CreateTemp(t.TempDir(), "scalibr-qcow2-out-*.raw")
	if err != nil {
		t.Fatalf("CreateTemp output: %v", err)
	}
	outFile.Close()
	outputPath := outFile.Name()

	t.Logf("Malicious QCOW2: %d bytes on disk", 116)
	t.Logf("ClusterBits: %d => clusterSize = %d bytes (~%d MB)",
		clusterBits, uint64(1)<<clusterBits, (uint64(1)<<clusterBits)>>20)

	var msBefore, msAfter runtime.MemStats
	runtime.ReadMemStats(&msBefore)

	convertErr := convertQCOW2ToRaw(inputPath, outputPath, "")

	runtime.ReadMemStats(&msAfter)
	allocMB := (msAfter.TotalAlloc - msBefore.TotalAlloc) >> 20

	t.Logf("convertQCOW2ToRaw err: %v", convertErr)
	t.Logf("TotalAlloc delta: %d MB", allocMB)

	if convertErr == nil {
		t.Errorf("expected error for malicious ClusterBits=%d, got nil", clusterBits)
	}
	if allocMB > 50 {
		t.Errorf("TotalAlloc delta %d MB exceeds 50 MB — bounds check is missing or ineffective", allocMB)
	}
}
