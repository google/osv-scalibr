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

// Package ova provides an extractor for extracting software inventories from OVA archives
package ova

import (
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
	// Name is the unique identifier for the ova extractor.
	Name = "embeddedfs/ova"
)

// Extractor implements the filesystem.Extractor interface for ova.
type Extractor struct{}

// New returns a new ova extractor.
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

// FileRequired checks if the file is a .ova file based on its extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return strings.HasSuffix(strings.ToLower(path), ".ova")
}

// Extract returns an Inventory with embedded filesystems which contains a mount function for the filesystem in the .ova file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Check wether input.Reader is nil or not.
	// This check is crucial because tar.NewReader doesn't validate the input,
	// it simply wraps it around tar.Reader.
	if input.Reader == nil {
		return inventory.Inventory{}, errors.New("input.Reader is nil")
	}

	tempDir, err := common.TARToTempDir(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("common.TARToTempDir(%q): %w", input.Path, err)
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
	var inv inventory.Inventory
	inv.EmbeddedFSs = append(inv.EmbeddedFSs, &inventory.EmbeddedFS{
		Path:          input.Path,
		GetEmbeddedFS: getEmbeddedFS,
	})
	return inv, nil
}
