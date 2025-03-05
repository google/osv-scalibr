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
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"
)

const (
	// filePermission represents the permission bits for a file, which are minimal since files in the
	// layer scanning use case are read-only.
	filePermission = 0600
	// dirPermission represents the permission bits for a directory, which are minimal since
	// directories in the layer scanning use case are read-only.
	dirPermission = 0700
)

// fileNode represents a file in a virtual filesystem.
type fileNode struct {
	// extractDir and originLayerID are used to construct the real file path of the fileNode.
	extractDir    string
	originLayerID string

	// isWhiteout is true if the fileNode represents a whiteout file
	isWhiteout bool

	// virtualPath is the path of the fileNode in the virtual filesystem.
	virtualPath string
	// targetPath is reserved for symlinks. It is the path that the symlink points to.
	targetPath string

	// size, mode, and modTime are used to implement the fs.FileInfo interface.
	size    int64
	mode    fs.FileMode
	modTime time.Time

	// file is the file object for the real file referred to by the fileNode.
	file *os.File
}

// ========================================================
// fs.File METHODS
// ========================================================

// Stat returns the file info of real file referred by the fileNode.
func (f *fileNode) Stat() (fs.FileInfo, error) {
	if f.isWhiteout {
		return nil, fs.ErrNotExist
	}

	return f, nil
}

// Read reads the real file referred to by the fileNode.
func (f *fileNode) Read(b []byte) (n int, err error) {
	if f.isWhiteout {
		return 0, fs.ErrNotExist
	}
	if f.file == nil {
		f.file, err = os.Open(f.RealFilePath())
	}
	if err != nil {
		return 0, err
	}

	return f.file.Read(b)
}

// ReadAt reads the real file referred to by the fileNode at a specific offset.
func (f *fileNode) ReadAt(b []byte, off int64) (n int, err error) {
	if f.isWhiteout {
		return 0, fs.ErrNotExist
	}
	if f.file == nil {
		f.file, err = os.Open(f.RealFilePath())
	}
	if err != nil {
		return 0, err
	}

	return f.file.ReadAt(b, off)
}

func (f *fileNode) Seek(offset int64, whence int) (n int64, err error) {
	if f.isWhiteout {
		return 0, fs.ErrNotExist
	}
	if f.file == nil {
		f.file, err = os.Open(f.RealFilePath())
	}
	if err != nil {
		return 0, err
	}

	return f.file.Seek(offset, whence)
}

// Close closes the real file referred to by the fileNode and resets the file field.
func (f *fileNode) Close() error {
	if f.file != nil {
		err := f.file.Close()
		f.file = nil

		return err
	}

	return nil
}

// RealFilePath returns the real file path of the fileNode. This is the concatenation of the
// root image extract directory, origin layer ID, and the virtual path.
func (f *fileNode) RealFilePath() string {
	return filepath.Join(f.extractDir, f.originLayerID, filepath.FromSlash(f.virtualPath))
}

// ========================================================
// fs.DirEntry METHODS
// ========================================================

// Name returns the name of the fileNode. Name is also used to implement the fs.FileInfo interface.
func (f *fileNode) Name() string {
	_, filename := path.Split(f.virtualPath)

	return filename
}

// IsDir returns whether the fileNode represents a directory. IsDir is also used to implement the
// fs.FileInfo interface.
func (f *fileNode) IsDir() bool {
	return f.Type().IsDir()
}

// Type returns the file type of file represented by the fileNode.
func (f *fileNode) Type() fs.FileMode {
	return f.mode
}

// Info returns the FileInfo of the file represented by the fileNode.
func (f *fileNode) Info() (fs.FileInfo, error) {
	return f.Stat()
}

// ========================================================
// fs.FileInfo METHODS
// ========================================================
func (f *fileNode) Size() int64 {
	return f.size
}

func (f *fileNode) Mode() fs.FileMode {
	return f.mode
}

func (f *fileNode) ModTime() time.Time {
	return f.modTime
}

func (f *fileNode) Sys() any {
	return nil
}
