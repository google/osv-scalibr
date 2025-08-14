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

// Package extracttest provides testing utilities for extractors.
package extracttest

import (
	"io/fs"
	"time"
)

// FakeFileAPI implements filesystem.FileAPI for testing.
type FakeFileAPI struct {
	Path     string
	FileInfo FakeFileInfo
}

// Path returns the file path.
func (f FakeFileAPI) Path() string {
	return f.Path
}

// Stat returns the file info.
func (f FakeFileAPI) Stat() (fs.FileInfo, error) {
	return f.FileInfo, nil
}

// FakeFileInfo implements fs.FileInfo for testing.
type FakeFileInfo struct {
	FileName string
	FileSize int64
	FileMode fs.FileMode
	ModTime  time.Time
	IsDir    bool
}

// Name returns the file name.
func (f FakeFileInfo) Name() string {
	if f.FileName != "" {
		return f.FileName
	}
	return "test.txt"
}

// Size returns the file size.
func (f FakeFileInfo) Size() int64 {
	return f.FileSize
}

// Mode returns the file mode.
func (f FakeFileInfo) Mode() fs.FileMode {
	if f.FileMode != 0 {
		return f.FileMode
	}
	return 0644
}

// ModTime returns the modification time.
func (f FakeFileInfo) ModTime() time.Time {
	if !f.ModTime.IsZero() {
		return f.ModTime
	}
	return time.Now()
}

// IsDir returns whether this is a directory.
func (f FakeFileInfo) IsDir() bool {
	return f.IsDir
}

// Sys returns the underlying data source.
func (f FakeFileInfo) Sys() interface{} {
	return nil
}