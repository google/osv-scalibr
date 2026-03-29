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
	"fmt"
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
	"github.com/google/osv-scalibr/tempdir"
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
	qcow2Path, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to get real path for %s: %w", input.Path, err)
	}

	// If called on a virtual FS, clean up the temporary directory
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(qcow2Path)
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("os.RemoveAll(%q): %v\n", dir, err)
			}
		}()
	}

	// Create the plugin directory.
	// Disk layout will be similar to the following in the OS sets temporary directory:
	// ├── osv-scalibr-run-953505549
	// │				└── extractor
	// │				    └── qcow2
	// |						└── valid.qcow2 							<--- File discovered by the extractor
	// │				        	├── partition-1-ext4					<--- A folder containing partition data
	// │				        	│				└── private-key1.pem
	// │				        	├── partition-2-exfat
	// │				        	│				└── private-key2.pem
	// │				        	├── partition-3-fat32
	// │				        	│				└── private-key3.pem
	// │				        	├── partition-4-ntfs
	// │				        	│				└── private-key4.pem
	// │				        	└── qcow2-12345.raw						<--- Converted disk image
	pluginDir, err := tempdir.CreateExtractorDir("qcow2", input.Path)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create plugin dir: %w", err)
	}

	// Create a temporary file for the raw disk image
	rawDiskIMGPath, _, err := tempdir.CreateFile(pluginDir, "qcow2-*.raw")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary raw file: %w", err)
	}

	// Convert QCOW2 to raw
	if err := convertQCOW2ToRaw(qcow2Path, rawDiskIMGPath, e.password); err != nil {
		os.Remove(rawDiskIMGPath)
		return inventory.Inventory{}, fmt.Errorf("failed to convert %s to raw image: %w", input.Path, err)
	}

	// Retrieve all partitions and the associated disk handle from the raw disk image.
	partitionList, disk, err := common.GetDiskPartitions(rawDiskIMGPath)
	if err != nil {
		os.Remove(rawDiskIMGPath)
		return inventory.Inventory{}, err
	}

	// Create a reference counter for the temporary file
	var refCount int32
	var refMu sync.Mutex

	// Create an Embedded filesystem for each valid partition
	var embeddedFSs []*inventory.EmbeddedFS
	for i, p := range partitionList {
		partitionIndex := i + 1 // go-diskfs uses 1-based indexing
		getEmbeddedFS := common.NewPartitionEmbeddedFSGetter("qcow2", partitionIndex, p, disk, pluginDir, rawDiskIMGPath, &refMu, &refCount)
		embeddedFSs = append(embeddedFSs, &inventory.EmbeddedFS{
			Path:          fmt.Sprintf("%s:%d", input.Path, partitionIndex),
			GetEmbeddedFS: getEmbeddedFS,
		})
	}
	return inventory.Inventory{EmbeddedFSs: embeddedFSs}, nil
}
