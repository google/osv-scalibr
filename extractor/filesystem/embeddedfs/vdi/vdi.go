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

// Package vdi provides an extractor for extracting software inventories from VirtualBox's VDI disk images
package vdi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique identifier for the vdi extractor.
	Name = "embeddedfs/vdi"
	// Signature is always 0xBEDA107F.
	// Reference: https://github.com/qemu/qemu/blob/ed698be7700160c74d24ef7830adccd2a28d840a/block/vdi.c#L107-L108
	// Reference : https://forums.virtualbox.org/viewtopic.php?t=8046
	Signature = 0xBEDA107F

	// Reference: https://github.com/qemu/qemu/blob/ed698be7700160c74d24ef7830adccd2a28d840a/block/vdi.c#L113-L115
	vdiTypeDynamic = 1
	vdiTypeStatic  = 2

	// Reference: https://github.com/qemu/qemu/blob/ed698be7700160c74d24ef7830adccd2a28d840a/block/vdi.c#L125-L131
	vdiUnallocated = 0xFFFFFFFF
	vdiDiscarded   = 0xFFFFFFFE
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

var headerSize = int64(binary.Size(&header{}))

// Extractor implements the filesystem.Extractor interface for vdi.
type Extractor struct {
	// maxFileSizeBytes is the maximum size of an archive file that can be traversed.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored.
	maxFileSizeBytes int64
}

// New returns a new VDI extractor.
// New returns a new archive extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxSize := cfg.MaxFileSizeBytes
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.VDIConfig { return c.GetVdi() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxSize = specific.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxSize}, nil
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
	if !strings.HasSuffix(strings.ToLower(path), ".vdi") {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}

	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		return false
	}

	return true
}

// Extract returns an Inventory with embedded filesystems which contains mount functions for each filesystem in the .vdi file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	vdiPath, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to get real path for %s: %w", input.Path, err)
	}
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(vdiPath)
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("os.RemoveAll(%q): %v", dir, err)
			}
		}()
	}

	vdiFile, err := os.Open(vdiPath)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to open VDI image %s: %w", vdiPath, err)
	}
	defer vdiFile.Close()

	// Create a temporary file for the raw disk image
	tmpRaw, err := os.CreateTemp("", "scalibr-vdi-raw-*.raw")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary raw file: %w", err)
	}
	tmpRawPath := tmpRaw.Name()

	// Convert VDI to raw
	if err := convertVDIToRaw(vdiFile, tmpRaw); err != nil {
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to convert %s to raw image: %w", input.Path, err)
	}

	// Retrieve all partitions and the associated disk handle from the raw disk image.
	partitionList, disk, err := common.GetDiskPartitions(tmpRawPath)
	if err != nil {
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

type sparseWriter interface {
	io.Writer
	io.Seeker
	Truncate(size int64) error
}

// convertVDIToRaw converts a VDI image to a raw image.
func convertVDIToRaw(in io.ReaderAt, out sparseWriter) error {
	var hdr header
	if err := binary.Read(io.NewSectionReader(in, 0, headerSize), binary.LittleEndian, &hdr); err != nil {
		return fmt.Errorf("failed to read VDI header: %w", err)
	}
	if hdr.Signature != Signature {
		return errors.New("not a valid VDI file (bad signature)")
	}
	if hdr.DiskSize > math.MaxInt64 {
		return fmt.Errorf("VDI disk size %d exceeds the maximum supported size", hdr.DiskSize)
	}

	switch hdr.ImageType {
	case vdiTypeDynamic:
		return convertDynamicVDIToRaw(in, out, &hdr)
	case vdiTypeStatic:
		return convertFixedVDIToRaw(in, out, &hdr)
	default:
		return fmt.Errorf("unsupported VDI type %d", hdr.ImageType)
	}
}

func convertDynamicVDIToRaw(in io.ReaderAt, out sparseWriter, hdr *header) error {
	if hdr.BlockSize == 0 {
		return errors.New("invalid VDI block size 0")
	}
	// The map must cover the disk
	// Reference: https://github.com/qemu/qemu/blob/ed698be7700160c74d24ef7830adccd2a28d840a/block/vdi.c#L454-L461
	if uint64(hdr.BlocksInImage)*uint64(hdr.BlockSize) < hdr.DiskSize {
		return fmt.Errorf("VDI block count %d cannot cover disk size %d with block size %d",
			hdr.BlocksInImage, hdr.DiskSize, hdr.BlockSize)
	}

	mapOffset := max(headerSize, int64(hdr.OffsetBmap))
	mapSize := int64(hdr.BlocksInImage) * 4

	// Verify the full block map exists without loading it into memory.
	if mapSize > 0 {
		var last [1]byte
		if _, err := io.ReadFull(io.NewSectionReader(in, mapOffset+mapSize-1, 1), last[:]); err != nil {
			return fmt.Errorf("failed to read block map: %w", err)
		}
	}

	mapReader := io.NewSectionReader(in, mapOffset, mapSize)
	stride := uint64(hdr.BlockSize) + uint64(hdr.BlockExtra)
	seenBlocks := make(map[uint32]struct{})
	var mapEntry [4]byte
	for i := uint32(0); i < hdr.BlocksInImage; i++ {
		virtOffset := uint64(i) * uint64(hdr.BlockSize)
		if virtOffset >= hdr.DiskSize {
			break
		}
		writeSize := min(uint64(hdr.BlockSize), hdr.DiskSize-virtOffset)
		if _, err := io.ReadFull(mapReader, mapEntry[:]); err != nil {
			return fmt.Errorf("failed to read block map entry %d: %w", i, err)
		}
		idx := binary.LittleEndian.Uint32(mapEntry[:])
		if idx == vdiUnallocated || idx == vdiDiscarded {
			// Keep unallocated blocks sparse in the raw output.
			if _, err := out.Seek(int64(writeSize), io.SeekCurrent); err != nil {
				return fmt.Errorf("failed to create sparse hole at guest offset %d: %w", virtOffset, err)
			}
			continue
		}
		// Reject repeated physical blocks before copying their data.
		// Reference: https://github.com/qemu/qemu/blob/ed698be7700160c74d24ef7830adccd2a28d840a/block/vdi.c#L298-L312
		if _, seen := seenBlocks[idx]; seen {
			return fmt.Errorf("duplicate VDI block index %d at map entry %d", idx, i)
		}
		seenBlocks[idx] = struct{}{}

		// Physical location of block
		phys := int64(hdr.OffsetData) + int64(uint64(idx)*stride) + int64(hdr.BlockExtra)
		_, err := io.CopyN(out, io.NewSectionReader(in, phys, int64(writeSize)), int64(writeSize))
		if err != nil {
			return fmt.Errorf("failed to read data block: %w", err)
		}
	}
	if err := out.Truncate(int64(hdr.DiskSize)); err != nil {
		return fmt.Errorf("failed to set raw image size: %w", err)
	}
	return nil
}

func convertFixedVDIToRaw(in io.ReaderAt, out sparseWriter, hdr *header) error {
	dataOffset := max(headerSize, int64(hdr.OffsetData))
	_, err := io.CopyN(out, io.NewSectionReader(in, dataOffset, int64(hdr.DiskSize)), int64(hdr.DiskSize))
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
