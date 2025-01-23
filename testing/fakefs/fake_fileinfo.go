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

// Package fakefs provides a fake file system implementation for testing.
package fakefs

import (
	"io/fs"
	"time"
)

// FakeFileInfo is a fake implementation of fs.FileInfo.
type FakeFileInfo struct {
	FileName    string
	FileSize    int64
	FileMode    fs.FileMode
	FileModTime time.Time
}

// Name returns the name of the file.
func (i FakeFileInfo) Name() string {
	return i.FileName
}

// Size returns the size of the file.
func (i FakeFileInfo) Size() int64 {
	return i.FileSize
}

// Mode returns the mode of the file.
func (i FakeFileInfo) Mode() fs.FileMode {
	return i.FileMode
}

// ModTime returns the modification time of the file.
func (i FakeFileInfo) ModTime() time.Time {
	return i.FileModTime
}

// IsDir returns true if the file is a directory.
func (i FakeFileInfo) IsDir() bool {
	return i.FileMode.IsDir()
}

// Sys is an implementation of FileInfo.Sys() that returns nothing (nil).
func (i FakeFileInfo) Sys() any {
	return nil
}
