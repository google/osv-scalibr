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
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
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

// FileRequired checks if the file is a .ova file based on its extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return strings.HasSuffix(strings.ToLower(path), ".ova")
}

// Extract returns an Inventory with embedded filesystems which contains a mount function for the filesystem in the .ova file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	ovaPath, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to get real path for %s: %w", input.Path, err)
	}

	// Initialize empty inventory.
	inv := inventory.Inventory{Packages: []*extractor.Package{}}

	// If called on a virtual FS, clean up the temporary directory containing the ova
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(ovaPath)
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("os.RemoveAll(%q): %v\n", dir, err)
			}
		}()
	}

	// Open ova file to check if it's a tar
	f, err := os.Open(ovaPath)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to open ova file %s: %w", ovaPath, err)
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return inventory.Inventory{}, fmt.Errorf("failed to read ova header: %w", err)
	}
	if n < 262 {
		return inventory.Inventory{}, fmt.Errorf("%s is too small to be a tar archive", ovaPath)
	}
	if !isTar(buf) {
		return inventory.Inventory{}, fmt.Errorf("%s is not a valid tar archive", ovaPath)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to seek at the beginning of the ova file: %w", err)
	}

	// Create a temporary directory for extracted files
	tempDir, err := os.MkdirTemp("", "scalibr-ova-")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	// Extract the tar archive
	var extractErr error
	var locations []string
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			extractErr = fmt.Errorf("failed to read tar header: %w", err)
			break
		}

		target := filepath.Join(tempDir, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				extractErr = fmt.Errorf("failed to create directory %s: %w", target, err)
				break
			}
		case tar.TypeReg:
			dir := filepath.Dir(target)
			if err := os.MkdirAll(dir, 0755); err != nil {
				extractErr = fmt.Errorf("failed to create directory %s: %w", dir, err)
				break
			}
			outFile, err := os.Create(target)
			if err != nil {
				extractErr = fmt.Errorf("failed to create file %s: %w", target, err)
				break
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				extractErr = fmt.Errorf("failed to copy file %s: %w", target, err)
				break
			}
			outFile.Close()
			locations = append(locations, target)
		default:
			// Skip other types (symlinks, etc.) for now
			continue
		}
	}

	if extractErr != nil {
		return inventory.Inventory{}, extractErr
	}

	getEmbeddedFS := func(ctx context.Context) (scalibrfs.FS, error) {
		return &ovaDirFS{
			fs:     scalibrfs.DirFS(tempDir),
			tmpDir: tempDir,
		}, nil
	}

	// Add as a package to trigger sub-extraction later.
	inv.Packages = append(inv.Packages, &extractor.Package{
		Name:      "OVA",
		PURLType:  purl.TypeOva,
		Locations: locations,
	})

	inv.EmbeddedFSs = append(inv.EmbeddedFSs, &inventory.EmbeddedFS{
		Path:          ovaPath,
		GetEmbeddedFS: getEmbeddedFS,
	})
	return inv, nil
}

// isTar checks if the buffer starts with TAR magic.
func isTar(buf []byte) bool {
	return string(buf[257:262]) == "ustar"
}

// ovaDirFS wraps scalibrfs.DirFS to include cleanup
type ovaDirFS struct {
	fs     scalibrfs.FS
	tmpDir string
}

func (o *ovaDirFS) Open(name string) (fs.File, error) {
	return o.fs.Open(name)
}

func (o *ovaDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return o.fs.ReadDir(name)
}

func (o *ovaDirFS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	return o.fs.Stat(name)
}

func (o *ovaDirFS) Close() error {
	return nil
}

// fileInfo is a simple implementation of fs.FileInfo for the root directory
type fileInfo struct {
	name    string
	isDir   bool
	modTime time.Time
}

func (fi *fileInfo) Name() string {
	return fi.name
}

func (fi *fileInfo) Size() int64 {
	return 0
}

func (fi *fileInfo) Mode() fs.FileMode {
	if fi.isDir {
		return fs.ModeDir | 0755
	}
	return 0644
}

func (fi *fileInfo) ModTime() time.Time {
	return fi.modTime
}

func (fi *fileInfo) IsDir() bool {
	return fi.isDir
}

func (fi *fileInfo) Sys() any {
	return nil
}
