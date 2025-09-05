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

package image

import (
	"errors"
	"io"
	"io/fs"
	"path"
	"time"
)

var (
	errCannotReadVirutalDirectory = errors.New("cannot read directory")
	errCannotReadVirtualFile      = errors.New("cannot read file")
)

// VirtualFile represents a file in a virtual filesystem.
type VirtualFile struct {
	// reader provides `Read()`, `Seek()`, `ReadAt()` and `Size()` operations on
	// the content of this file similar to `io.SectionReader`.
	// The file can still be read after closing as closing only resets the cursor.
	// If the file is a directory, operations succeed with 0 byte reads.
	reader *io.SectionReader

	// isWhiteout is true if the VirtualFile represents a whiteout file
	isWhiteout bool
	// virtualPath is the path of the VirtualFile in the virtual filesystem.
	virtualPath string
	// targetPath is reserved for symlinks. It is the path that the symlink points to.
	targetPath string

	// size, mode, and modTime are used to implement the fs.FileInfo interface.
	size    int64
	mode    fs.FileMode
	modTime time.Time
}

// ========================================================
// fs.File METHODS
// ========================================================

// validateVirtualFile validates that the VirtualFile is in a valid state to be read from.
func validateVirtualFile(f *VirtualFile) error {
	if f.isWhiteout {
		return fs.ErrNotExist
	}
	if f.IsDir() {
		return errCannotReadVirutalDirectory
	}

	if f.reader == nil {
		return errCannotReadVirtualFile
	}

	return nil
}

// Stat returns the VirtualFile itself since it implements the fs.FileInfo interface.
func (f *VirtualFile) Stat() (fs.FileInfo, error) {
	if f.isWhiteout {
		return nil, fs.ErrNotExist
	}
	return f, nil
}

// Read reads the real file contents referred to by the VirtualFile.
func (f *VirtualFile) Read(b []byte) (n int, err error) {
	if err := validateVirtualFile(f); err != nil {
		return 0, err
	}
	return f.reader.Read(b)
}

// ReadAt reads the real file contents referred to by the VirtualFile at a specific offset.
func (f *VirtualFile) ReadAt(b []byte, off int64) (n int, err error) {
	if err := validateVirtualFile(f); err != nil {
		return 0, err
	}
	return f.reader.ReadAt(b, off)
}

// Seek sets the read cursor of the file contents represented by the VirtualFile.
func (f *VirtualFile) Seek(offset int64, whence int) (n int64, err error) {
	if err := validateVirtualFile(f); err != nil {
		return 0, err
	}
	return f.reader.Seek(offset, whence)
}

// Close resets the read cursor of the file contents represented by the VirtualFile.
func (f *VirtualFile) Close() error {
	// Don't do anything for directories.
	if f.IsDir() {
		return nil
	}

	if err := validateVirtualFile(f); err != nil {
		return err
	}
	_, err := f.reader.Seek(0, io.SeekStart)
	return err
}

// ========================================================
// fs.DirEntry METHODS
// ========================================================

// Name returns the name of the VirtualFile. Name is also used to implement the fs.FileInfo interface.
func (f *VirtualFile) Name() string {
	_, filename := path.Split(f.virtualPath)
	return filename
}

// IsDir returns whether the VirtualFile represents a directory. IsDir is also used to implement the
// fs.FileInfo interface.
func (f *VirtualFile) IsDir() bool {
	return f.Type().IsDir()
}

// Type returns the file type of file represented by the VirtualFile.
func (f *VirtualFile) Type() fs.FileMode {
	return f.mode
}

// Info returns the FileInfo of the file represented by the VirtualFile.
func (f *VirtualFile) Info() (fs.FileInfo, error) {
	return f.Stat()
}

// ========================================================
// fs.FileInfo METHODS
// ========================================================

// Size returns the size of the file.
func (f *VirtualFile) Size() int64 {
	return f.size
}

// Mode returns the mode of the file.
func (f *VirtualFile) Mode() fs.FileMode {
	return f.mode
}

// ModTime returns the modification time of the file.
func (f *VirtualFile) ModTime() time.Time {
	return f.modTime
}

// Sys is an implementation of FileInfo.Sys() that returns nothing (nil).
func (f *VirtualFile) Sys() any {
	return nil
}
