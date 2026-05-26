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

package vmdk

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"os"
	"testing"
)

// TestConvertVMDKZlibBombRejected verifies that a stream-optimized VMDK
// containing a decompression bomb (small compressed grain expanding far beyond
// one grain size) is rejected rather than causing unbounded memory allocation.
func TestConvertVMDKZlibBombRejected(t *testing.T) {
	// Craft a stream-optimized VMDK with a single grain whose zlib payload
	// decompresses to more than grainBytes (65536 bytes).
	const grainSize = 128 // sectors per grain
	const overhead = 4

	// Compress 1 MB of zeros — decompresses to 1 MB >> grainBytes (65536).
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(bytes.Repeat([]byte{0}, 1<<20)); err != nil { // 1 MB
		t.Fatalf("zw.Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zw.Close: %v", err)
	}
	compressed := zbuf.Bytes()

	// Build header: CompressAlgorithm=1 → isStream=true; GDOffset=2 → skip readFooterIfGDAtEnd.
	var hdr sparseExtentHeader
	hdr.MagicNumber = SparseMagic
	hdr.Version = 1
	hdr.Flags = (1 << 16) | (1 << 17) // HAS_COMPRESSED | HAS_METADATA
	hdr.Capacity = 0x10000
	hdr.GrainSize = grainSize
	hdr.DescriptorOffset = 1
	hdr.DescriptorSize = 1
	hdr.NumGTEsPerGT = SectorSize / 4
	hdr.GDOffset = 2
	hdr.OverHead = overhead
	hdr.CompressAlgorithm = 1

	var buf bytes.Buffer
	bwrite := func(v any) {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			t.Fatalf("binary.Write: %v", err)
		}
	}

	bwrite(&hdr)
	// Pad to OverHead sectors.
	buf.Write(make([]byte, overhead*SectorSize-buf.Len()))

	// Grain marker: val(8 LE) + size(4 LE) + compressed payload, padded to sector.
	bwrite(uint64(0))               // LBA
	bwrite(uint32(len(compressed))) // compressed size
	buf.Write(compressed)
	if pad := (SectorSize - (buf.Len() % SectorSize)) % SectorSize; pad > 0 {
		buf.Write(make([]byte, pad))
	}

	// EOS marker.
	bwrite(uint64(0)) // val
	bwrite(uint32(0)) // size=0
	bwrite(uint32(0)) // type=EOS
	buf.Write(make([]byte, SectorSize-16))

	// Write to temp file (convertVMDKToRaw requires a file path).
	tmp, err := os.CreateTemp(t.TempDir(), "vmdk-zlib-bomb-*.vmdk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	outRaw, err := os.CreateTemp(t.TempDir(), "vmdk-zlib-bomb-out-*.raw")
	if err != nil {
		t.Fatal(err)
	}
	outRaw.Close()

	err = convertVMDKToRaw(tmp.Name(), outRaw.Name())
	if err == nil {
		t.Error("convertVMDKToRaw: want error for decompression bomb, got nil")
	}
}
