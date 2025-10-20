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

// Package archive provides an extractor for extracting software inventories from archives
package archive

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique identifier for the archive extractor.
	Name = "embeddedfs/archive"
)

// Extractor implements the filesystem.Extractor interface for archive extraction.
type Extractor struct{}

// New returns a new archive extractor.
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

// FileRequired checks if the file is a supported archive.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".tar.gz")
}

// Extract returns an Inventory with embedded filesystems for the given archive file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Reader == nil {
		return inventory.Inventory{}, errors.New("input.Reader is nil")
	}

	var tempDir string
	var err error
	if strings.HasSuffix(input.Path, ".tar") {
		tempDir, err = common.TARToTempDir(input.Reader)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("common.TARToTempDir(%q): %w", input.Path, err)
		}
	} else if strings.HasSuffix(input.Path, ".tar.gz") {
		reader, err := gzip.NewReader(input.Reader)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("gzip.NewReader(%q): %w", input.Path, err)
		}
		tempDir, err = common.TARToTempDir(reader)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("common.TARToTempDir(%q): %w", input.Path, err)
		}
	} else {
		return inventory.Inventory{}, fmt.Errorf("%q not a supported archive format", input.Path)
	}

	var refCount int32 = 1
	var refMu sync.Mutex
	getEmbeddedFS := func(ctx context.Context) (scalibrfs.FS, error) {
		return &common.EmbeddedDirFS{
			FS:       scalibrfs.DirFS(tempDir),
			File:     nil,
			TmpPaths: []string{tempDir},
			RefCount: &refCount,
			RefMu:    &refMu,
		}, nil
	}
	return inventory.Inventory{
		EmbeddedFSs: []*inventory.EmbeddedFS{
			{
				Path:          input.Path,
				GetEmbeddedFS: getEmbeddedFS,
			}},
	}, nil
}
