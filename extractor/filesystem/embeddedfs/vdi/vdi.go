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
	"path/filepath"
	"strings"
	"sync"

	"github.com/diskfs/go-diskfs"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	scalibrfs "github.com/google/osv-scalibr/fs"
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

// NewDefault returns a New()
func NewDefault() filesystem.Extractor {
	return New()
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
	vdiPath, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to get real path for %s: %w", input.Path, err)
	}
	// If called on a virtual FS, clean up the temporary directory
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(vdiPath)
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("os.RemoveAll(%q): %v\n", dir, err)
			}
		}()
	}

	// Create a temporary file for the raw disk image
	tmpRaw, err := os.CreateTemp("", "scalibr-vdi-raw-*.raw")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary raw file: %w", err)
	}
	tmpRawPath := tmpRaw.Name()

	// Convert VDI to raw
	if err := convertVDIToRaw(vdiPath, tmpRawPath); err != nil {
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to convert %s to raw image: %w", vdiPath, err)
	}

	// Open the raw disk image with go-diskfs
	disk, err := diskfs.Open(tmpRawPath, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to open raw disk image %s: %w", tmpRawPath, err)
	}

	// Get the partition table
	partitions, err := disk.GetPartitionTable()
	if err != nil {
		disk.Close()
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to get partition table: %w", err)
	}
	partitionList := partitions.GetPartitions()
	if len(partitionList) == 0 {
		disk.Close()
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, errors.New("no partitions found in raw disk image")
	}

	// Create a reference counter for the temporary file
	var refCount int32
	var refMu sync.Mutex

	// Create an Embedded filesystem for each valid partition
	var embeddedFSs []*inventory.EmbeddedFS
	for i, p := range partitionList {
		partitionIndex := i + 1 // go-diskfs uses 1-based indexing
		getEmbeddedFS := func(ctx context.Context) (scalibrfs.FS, error) {
			// Open raw image for filesystem parsers
			f, err := os.Open(tmpRawPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open raw image %s: %w", tmpRawPath, err)
			}

			// Get partition offset and size (already multiplied by sector size)
			offset := p.GetStart()
			size := p.GetSize()
			section := io.NewSectionReader(f, offset, size)
			fsType := common.DetectFilesystem(section, 0)

			// Create a temporary directory for extracted files
			tempDir, err := os.MkdirTemp("", fmt.Sprintf("scalibr-vdi-%s-%d-", fsType, partitionIndex))
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("failed to create temporary directory for %s partition %d: %w", fsType, partitionIndex, err)
			}

			params := common.GenerateFSParams{
				File:           f,
				Disk:           disk,
				Section:        section,
				PartitionIndex: partitionIndex,
				TempDir:        tempDir,
				TmpRawPath:     tmpRawPath,
				RefMu:          &refMu,
				RefCount:       &refCount,
			}

			var fsys scalibrfs.FS
			switch fsType {
			case "ext4":
				fsys, err = common.GenerateEXTFS(params)
			case "FAT32":
				fsys, err = common.GenerateFAT32FS(params)
			case "exFAT":
				fsys, err = common.GenerateEXFATFS(params)
			case "NTFS":
				fsys, err = common.GenerateNTFSFS(params)
			default:
				fsys, err = nil, fmt.Errorf("unsupported filesystem type %s for partition %d", fsType, partitionIndex)
			}
			if err != nil {
				if fsType != "FAT32" {
					f.Close()
				}
				os.RemoveAll(tempDir)
				return nil, err
			}
			return fsys, nil
		}

		embeddedFSs = append(embeddedFSs, &inventory.EmbeddedFS{
			Path:          fmt.Sprintf("%s:%d", vdiPath, partitionIndex),
			GetEmbeddedFS: getEmbeddedFS,
		})
	}
	return inventory.Inventory{EmbeddedFSs: embeddedFSs}, nil
}

// VDI conversion functions

func convertVDIToRaw(inPath string, outPath string) error {
	f, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Read header
	var hdr header
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return err
	}

	// Sanity check: VDI signature should be 0xBEDA107F
	if hdr.Signature != Signature {
		return errors.New("not a valid VDI file (bad signature)")
	}

	// Open output
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch hdr.ImageType {
	// dynamic / sparse
	// Reference : https://github.com/qemu/qemu/blob/master/block/vdi.c#L114
	case 1:
		// Read block map
		if _, err := f.Seek(int64(hdr.OffsetBmap), io.SeekStart); err != nil {
			return err
		}
		indices := make([]uint32, hdr.BlocksInImage)
		if err := binary.Read(f, binary.LittleEndian, &indices); err != nil {
			return err
		}

		// Each block stride = BlockSize + BlockExtra
		stride := uint64(hdr.BlockSize) + uint64(hdr.BlockExtra)

		for i := range int(hdr.BlocksInImage) {
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
			if _, err := f.Seek(phys, io.SeekStart); err != nil {
				return err
			}
			if _, err := io.CopyN(out, f, int64(writeSize)); err != nil {
				return err
			}
		}
		return nil

	// static / fixed
	// Reference : https://github.com/qemu/qemu/blob/master/block/vdi.c#L115
	case 2:
		if _, err := f.Seek(int64(hdr.OffsetData), io.SeekStart); err != nil {
			return err
		}
		_, err = io.CopyN(out, f, int64(hdr.DiskSize))
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
