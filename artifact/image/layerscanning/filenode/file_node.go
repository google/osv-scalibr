// Copyright 2024 Google LLC
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

// Package filenode provides a fileNode type that can be used to represent files in a virtual file
// system.
package filenode

import (
	"io/fs"
	"os"
	"path"
)

type fileType int

const (
	// RegularFile represents a regular file in a file system.
	RegularFile fileType = iota
	// Dir represents a directory in a file system.
	Dir
)

type fileNode struct {
	extractDir    string
	originLayerID string
	fileType      fileType
	isWhiteout    bool
	virtualPath   string
	permission    fs.FileMode
	file          *os.File
}

// ========================================================
// fs.File METHODS
// ========================================================

// Stat returns the file info of real file referred by the fileNode.
// TODO(marioleyvajr): Need to replace the os stat permission with the permissions on the filenode.
func (f *fileNode) Stat() (fs.FileInfo, error) {
	if f.isWhiteout {
		return nil, fs.ErrNotExist
	}
	return os.Stat(f.RealFilePath())
}

// Read reads the real file referred to by the fileNode.
func (f *fileNode) Read(b []byte) (n int, err error) {
	if f.file == nil {
		f.file, err = os.Open(f.RealFilePath())
	}
	if err != nil {
		return 0, err
	}
	return f.file.Read(b)
}

// Close closes the real file referred to by the fileNode.
func (f *fileNode) Close() error {
	if f.file != nil {
		return f.file.Close()
	}
	return nil
}

// RealFilePath returns the real file path of the fileNode. This is the concatenation of the
// root image extract directory, origin layer ID, and the virtual path.
func (f *fileNode) RealFilePath() string {
	return path.Join(f.extractDir, f.originLayerID, f.virtualPath)
}

// ========================================================
// fs.DirEntry METHODS
// ========================================================

// Name returns the name of the fileNode.
func (f *fileNode) Name() string {
	_, filename := path.Split(f.virtualPath)
	return filename
}

// IsDir returns whether the fileNode represents a directory.
func (f *fileNode) IsDir() bool {
	return f.fileType == Dir
}

// Type returns the file type of file represented by the fileNode.
func (f *fileNode) Type() fs.FileMode {
	return f.permission
}

// FileInfo returns the FileInfo of the file represented by the fileNode.
func (f *fileNode) Info() (fs.FileInfo, error) {
	return f.Stat()
}
