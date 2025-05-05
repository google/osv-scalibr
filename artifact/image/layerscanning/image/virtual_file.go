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

// virtualFile represents a file in a virtual filesystem.
type virtualFile struct {
	// extractDir and layerDir are used to construct the real file path of the virtualFile.
	extractDir string
	layerDir   string

	// isWhiteout is true if the virtualFile represents a whiteout file
	isWhiteout bool

	// virtualPath is the path of the virtualFile in the virtual filesystem.
	virtualPath string
	// targetPath is reserved for symlinks. It is the path that the symlink points to.
	targetPath string

	// size, mode, and modTime are used to implement the fs.FileInfo interface.
	size    int64
	mode    fs.FileMode
	modTime time.Time

	// file is the file object for the real file referred to by the virtualFile.
	file *os.File
}

// ========================================================
// fs.File METHODS
// ========================================================

// Stat returns the file info of real file referred by the virtualFile.
func (f *virtualFile) Stat() (fs.FileInfo, error) {
	if f.isWhiteout {
		return nil, fs.ErrNotExist
	}
	return f, nil
}

// Read reads the real file referred to by the virtualFile.
func (f *virtualFile) Read(b []byte) (n int, err error) {
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

// ReadAt reads the real file referred to by the virtualFile at a specific offset.
func (f *virtualFile) ReadAt(b []byte, off int64) (n int, err error) {
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

func (f *virtualFile) Seek(offset int64, whence int) (n int64, err error) {
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

// Close closes the real file referred to by the virtualFile and resets the file field.
func (f *virtualFile) Close() error {
	if f.file != nil {
		err := f.file.Close()
		f.file = nil
		return err
	}
	return nil
}

// RealFilePath returns the real file path of the virtualFile. This is the concatenation of the
// root image extract directory, origin layer ID, and the virtual path.
func (f *virtualFile) RealFilePath() string {
	return filepath.Join(f.extractDir, f.layerDir, filepath.FromSlash(f.virtualPath))
}

// ========================================================
// fs.DirEntry METHODS
// ========================================================

// Name returns the name of the virtualFile. Name is also used to implement the fs.FileInfo interface.
func (f *virtualFile) Name() string {
	_, filename := path.Split(f.virtualPath)
	return filename
}

// IsDir returns whether the virtualFile represents a directory. IsDir is also used to implement the
// fs.FileInfo interface.
func (f *virtualFile) IsDir() bool {
	return f.Type().IsDir()
}

// Type returns the file type of file represented by the virtualFile.
func (f *virtualFile) Type() fs.FileMode {
	return f.mode
}

// Info returns the FileInfo of the file represented by the virtualFile.
func (f *virtualFile) Info() (fs.FileInfo, error) {
	return f.Stat()
}

// ========================================================
// fs.FileInfo METHODS
// ========================================================
func (f *virtualFile) Size() int64 {
	return f.size
}

func (f *virtualFile) Mode() fs.FileMode {
	return f.mode
}

func (f *virtualFile) ModTime() time.Time {
	return f.modTime
}

func (f *virtualFile) Sys() any {
	return nil
}
