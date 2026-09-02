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
	"os"
	"testing"
)

// TestConvertVDIOOMRejected verifies that a VDI image with an oversized
// BlocksInImage field is rejected before any large heap allocation occurs.
func TestConvertVDIOOMRejected(t *testing.T) {
	// BlocksInImage = 0x3FFFFFFF would request a ~4 GB indices slice.
	hdr := header{
		Signature:     Signature,
		Version:       0x00010001,
		ImageType:     1, // dynamic/sparse
		SectorSize:    512,
		BlockSize:     1 << 20,
		BlocksInImage: 0x3FFFFFFF,
		OffsetBmap:    512,
		OffsetData:    1024,
		DiskSize:      1 << 30,
	}
	copy(hdr.Text[:], "<<< Oracle VM VirtualBox Disk Image >>>\n")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &hdr); err != nil {
		t.Fatal(err)
	}

	out, err := os.CreateTemp(t.TempDir(), "vdi-oom-out-*.raw")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	if err := convertVDIToRaw(bytes.NewReader(buf.Bytes()), out); err == nil {
		t.Error("convertVDIToRaw: want error for oversized BlocksInImage, got nil")
	}
}
