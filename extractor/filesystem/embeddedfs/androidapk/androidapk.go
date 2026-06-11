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

// Package androidapk provides an extractor for extracting software inventories from Android .apk files
package androidapk

import (
	"context"
	"errors"
	"fmt"
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
	// Name is the unique identifier for the androidapk extractor.
	Name = "embeddedfs/androidapk"
)

// Extractor implements the filesystem.Extractor interface for Android apk.
type Extractor struct {
	// maxFileSizeBytes is the maximum size of an archive file that can be traversed.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored.
	maxFileSizeBytes int64
}

// New returns a new androidapk extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxSize := cfg.MaxFileSizeBytes
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.AndroidApkConfig { return c.GetAndroidApk() })
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

// FileRequired checks if the file is a .apk file based on its extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !strings.HasSuffix(strings.ToLower(path), ".apk") {
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

// Extract returns an Inventory with embedded filesystems which contains a mount function for the files in the .apk file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Check wether input.Reader is nil or not.
	if input.Reader == nil {
		return inventory.Inventory{}, errors.New("input.Reader is nil")
	}

	// Extract .apk file to a temporary directory so other plugins get to work on it.
	// This includes x509 certificates, maven metadata (if present), unpacked resource, and android dex files
	tempDir, err := common.ZIPToTempDir(input.Reader, e.maxFileSizeBytes)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("common.APKToTempDir(%q): %w", input.Path, err)
	}

	// manifest will hold normalized AndroidManifest.xml with resource references resolved from resources.arcs resource table file.
	manifest, normalizedManifest, err := loadManifest(tempDir)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("%s: manifest processing failed: %w", Name, err)
	}

	// Dump the normalized manifest to the disk so other plugins can work on it.
	// AndroidManifest.xml contains various secrets.
	// For reference, "Application MetaData: name="com.google.android.geo.API_KEY" value="AIzaSyAP-gfH3qvi6vgHZbSYwQ_XHqV_mXHhzIk"
	if err := dumpManifest(normalizedManifest, tempDir); err != nil {
		return inventory.Inventory{}, fmt.Errorf("%s: failed to dump manifest: %w", Name, err)
	}

	var inv inventory.Inventory
	packages := extractInventoryFromManifest(manifest, input.Path)
	inv.Packages = append(inv.Packages, packages...)

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

	inv.EmbeddedFSs = append(inv.EmbeddedFSs, &inventory.EmbeddedFS{
		Path:          input.Path,
		GetEmbeddedFS: getEmbeddedFS,
	})
	return inv, nil
}
