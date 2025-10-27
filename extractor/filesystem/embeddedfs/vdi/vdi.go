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

// Package vdi provides an extractor for extracting software inventories from VirtualBox's VDI disk images
package vdi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique identifier for the vdi extractor.
	Name = "embeddedfs/vdi"
	// Signature is always 0xBEDA107F.
	// Reference : https://github.com/qemu/qemu/blob/master/block/vdi.c#L107
	// Reference : https://forums.virtualbox.org/viewtopic.php?t=8046
	Signature = 0xBEDA107F
)

// header describes the on-disk VDI header structure.
type header struct {
	Text            [0x40]byte
	Signature       uint32
	Version         uint32
	HeaderSize      uint32
	ImageType       uint32
	ImageFlags      uint32
	Description     [256]byte
	OffsetBmap      uint32
	OffsetData      uint32
	Cylinders       uint32
	Heads           uint32
	Sectors         uint32
	SectorSize      uint32
	Unused1         uint32
	DiskSize        uint64
	BlockSize       uint32
	BlockExtra      uint32
	BlocksInImage   uint32
	BlocksAllocated uint32
	UUIDImage       [16]byte
	UUIDLastSnap    [16]byte
	UUIDLink        [16]byte
	UUIDParent      [16]byte
	Unused2         [7]uint64
}

// Extractor implements the filesystem.Extractor interface for vdi.
type Extractor struct{}

// New returns a new VDI extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// Name returns the name of the extractor.
func (e *Extractor) Name() string {
	return Name
}

// Version returns the version of the extractor.
func (e *Extractor) Version() int {
	return 0
}

// Requirements returns the requirements for the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired checks if the file is a .vdi file based on its extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return strings.HasSuffix(strings.ToLower(path), ".vdi")
}

// Extract returns an Inventory with embedded filesystems which contains mount functions for each filesystem in the .vdi file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Check wether input.Reader is nil or not.
	if input.Reader == nil {
		return inventory.Inventory{}, errors.New("input.Reader is nil")
	}

	// Create a temporary file for the raw disk image
	tmpRaw, err := os.CreateTemp("", "scalibr-vdi-raw-*.raw")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary raw file: %w", err)
	}
	tmpRawPath := tmpRaw.Name()

	// Convert VDI to raw
	if err := convertVDIToRaw(input.Reader, tmpRaw); err != nil {
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to convert %s to raw image: %w", input.Path, err)
	}

	// Retrieve all partitions and the associated disk handle from the raw disk image.
	partitionList, disk, err := common.GetDiskPartitions(tmpRawPath)
	if err != nil {
		disk.Close()
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, err
	}

	// Create a reference counter for the temporary file
	var refCount int32
	var refMu sync.Mutex

	// Create an Embedded filesystem for each valid partition
	var embeddedFSs []*inventory.EmbeddedFS
	for i, p := range partitionList {
		partitionIndex := i + 1 // go-diskfs uses 1-based indexing
		getEmbeddedFS := common.NewPartitionEmbeddedFSGetter("vdi", partitionIndex, p, disk, tmpRawPath, &refMu, &refCount)
		embeddedFSs = append(embeddedFSs, &inventory.EmbeddedFS{
			Path:          fmt.Sprintf("%s:%d", input.Path, partitionIndex),
			GetEmbeddedFS: getEmbeddedFS,
		})
	}
	return inventory.Inventory{EmbeddedFSs: embeddedFSs}, nil
}

// VDI conversion functions

// convertVDIToRaw converts a VDI image to a raw image using streaming I/O only (no Seek).
func convertVDIToRaw(in io.Reader, out io.Writer) error {
	var hdr header
	if err := binary.Read(in, binary.LittleEndian, &hdr); err != nil {
		return fmt.Errorf("failed to read VDI header: %w", err)
	}

	// Sanity check: VDI signature should be 0xBEDA107F
	if hdr.Signature != Signature {
		return errors.New("not a valid VDI file (bad signature)")
	}

	curPos := int64(binary.Size(hdr))

	switch hdr.ImageType {
	// dynamic / sparse
	// Reference : https://github.com/qemu/qemu/blob/master/block/vdi.c#L114
	case 1:
		// Skip to block map
		if int64(hdr.OffsetBmap) > curPos {
			if err := skipBytes(in, int64(hdr.OffsetBmap)-curPos); err != nil {
				return fmt.Errorf("failed to skip to block map: %w", err)
			}
			curPos = int64(hdr.OffsetBmap)
		}

		indices := make([]uint32, hdr.BlocksInImage)
		if err := binary.Read(in, binary.LittleEndian, &indices); err != nil {
			return fmt.Errorf("failed to read block map: %w", err)
		}
		curPos += int64(4 * len(indices))

		stride := uint64(hdr.BlockSize) + uint64(hdr.BlockExtra)
		for i := range indices {
			virtOffset := uint64(i) * uint64(hdr.BlockSize)
			writeSize := uint64(hdr.BlockSize)
			if virtOffset+writeSize > hdr.DiskSize {
				writeSize = hdr.DiskSize - virtOffset
			}

			idx := indices[i]
			// Reference : https://github.com/qemu/qemu/blob/master/block/vdi.c#L125-L131
			if idx == 0xFFFFFFFF || idx == 0xFFFFFFFE {
				// unallocated/discarded: write zeros
				if err := writeZeros(out, int64(writeSize)); err != nil {
					return err
				}
				continue
			}

			// Physical location of block
			phys := int64(hdr.OffsetData) + int64(uint64(idx)*stride) + int64(hdr.BlockExtra)
			if phys > curPos {
				if err := skipBytes(in, phys-curPos); err != nil {
					return fmt.Errorf("failed to skip to data block: %w", err)
				}
				curPos = phys
			}

			n, err := io.CopyN(out, in, int64(writeSize))
			curPos += n
			if err != nil {
				return fmt.Errorf("failed to read data block: %w", err)
			}
		}
		return nil

	// static / fixed
	// Reference : https://github.com/qemu/qemu/blob/master/block/vdi.c#L115
	case 2:
		if int64(hdr.OffsetData) > curPos {
			if err := skipBytes(in, int64(hdr.OffsetData)-curPos); err != nil {
				return err
			}
		}
		_, err := io.CopyN(out, in, int64(hdr.DiskSize))
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil

	default:
		return fmt.Errorf("unsupported VDI type %d", hdr.ImageType)
	}
}

func writeZeros(w io.Writer, n int64) error {
	buf := make([]byte, 64*1024)
	for n > 0 {
		chunk := int64(len(buf))
		if chunk > n {
			chunk = n
		}
		if _, err := w.Write(buf[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

func skipBytes(r io.Reader, n int64) error {
	buf := make([]byte, 64*1024)
	for n > 0 {
		chunk := int64(len(buf))
		if chunk > n {
			chunk = n
		}
		_, err := io.CopyN(io.Discard, r, chunk)
		if err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}
