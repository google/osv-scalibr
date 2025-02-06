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

// Package simplefileapi provides a fake implementation of the filesystem.FileAPI interface.
package simplefileapi

import (
	"io/fs"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

// SimpleFileAPI is a fake implementation of the filesystem.FileAPI interface.
type SimpleFileAPI struct {
	path string
	info fs.FileInfo
	err  error
}

// New creates a new FakeFileAPI.
func New(path string, info fs.FileInfo) *SimpleFileAPI {
	return &SimpleFileAPI{
		path: path,
		info: info,
	}
}

// Path returns the path of the file.
func (f SimpleFileAPI) Path() string {
	return f.path
}

// Stat returns the file information.
func (f SimpleFileAPI) Stat() (fs.FileInfo, error) {
	return f.info, f.err
}

var _ filesystem.FileAPI = SimpleFileAPI{}
