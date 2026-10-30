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

// Package qcow2 provides an extractor for extracting software inventories from QEMU's QCOW2 disk images.
package qcow2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique identifier for the qcow2 extractor.
	Name = "embeddedfs/qcow2"
)

// Extractor implements the filesystem.Extractor interface for qcow2.
type Extractor struct {
	// maxFileSizeBytes is the maximum size of an .qcow2 file that can be traversed.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored.
	maxFileSizeBytes int64
	// password is the password of an encrypted .qcow2 file
	password string
}

// New returns a new QCOW2 extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxSize := cfg.MaxFileSizeBytes
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.QCOW2Config { return c.GetQcow2() })
	var password string
	if specific != nil {
		if specific.GetMaxFileSizeBytes() > 0 {
			maxSize = specific.GetMaxFileSizeBytes()
		}
		if specific.GetPassword() != "" {
			password = specific.GetPassword()
		}
	}
	return &Extractor{maxFileSizeBytes: maxSize, password: password}, nil
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

// FileRequired checks if the file is a .qcow2 file based on its extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !strings.HasSuffix(strings.ToLower(path), ".qcow2") {
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

// Extract returns an Inventory with embedded filesystems which contains mount functions for each filesystem in the .qcow2 file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	sr, closer, err := openSectionReader(input)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to open %s: %w", input.Path, err)
	}
	defer closer.Close()

	// Create a temporary file for the raw disk image
	tmpRaw, err := os.CreateTemp("", "scalibr-qcow2-raw-*.raw")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary raw file: %w", err)
	}
	tmpRawPath := tmpRaw.Name()
	tmpRaw.Close()

	// Convert QCOW2 to raw
	if err := convertQCOW2ReaderToRaw(sr, tmpRawPath, e.password); err != nil {
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
		getEmbeddedFS := common.NewPartitionEmbeddedFSGetter("qcow2", partitionIndex, p, disk, tmpRawPath, &refMu, &refCount)
		embeddedFSs = append(embeddedFSs, &inventory.EmbeddedFS{
			Path:          fmt.Sprintf("%s:%d", input.Path, partitionIndex),
			GetEmbeddedFS: getEmbeddedFS,
		})
	}
	return inventory.Inventory{EmbeddedFSs: embeddedFSs}, nil
}

func openSectionReader(input *filesystem.ScanInput) (*io.SectionReader, io.Closer, error) {
	if input.Reader != nil {
		if input.Info == nil {
			return nil, nil, errors.New("input.Info is nil")
		}
		ra, err := scalibrfs.NewReaderAt(input.Reader)
		if err != nil {
			return nil, nil, err
		}
		return io.NewSectionReader(ra, 0, input.Info.Size()), io.NopCloser(nil), nil
	}
	fsys := input.FS
	if fsys == nil && input.Root != "" {
		fsys = scalibrfs.DirFS(input.Root)
	}
	if fsys != nil {
		f, err := fsys.Open(filepath.ToSlash(input.Path))
		if err != nil {
			return nil, nil, err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		ra, err := scalibrfs.NewReaderAt(f)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return io.NewSectionReader(ra, 0, fi.Size()), f, nil
	}
	return nil, nil, errors.New("no input filesystem or reader provided")
}
