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

// Package require provides an interface for specifying which files we are interested
// in during a container image extraction.
package require

import "io/fs"

// FileRequirer determines if a file is required to unpack.
type FileRequirer interface {
	FileRequired(path string, fileinfo fs.FileInfo) bool
}

// FileRequirerAll requires all files.
type FileRequirerAll struct{}

// FileRequired always returns true.
func (f *FileRequirerAll) FileRequired(path string, fileinfo fs.FileInfo) bool {
	return true
}

// FileRequirerNone requires no files.
type FileRequirerNone struct{}

// FileRequired always returns false.
func (f *FileRequirerNone) FileRequired(path string, fileinfo fs.FileInfo) bool {
	return false
}

// FileRequirerPaths requires files that match a collection of paths.
type FileRequirerPaths struct {
	required map[string]bool
}

// NewFileRequirerPaths returns a new FileRequirerPaths.
func NewFileRequirerPaths(required []string) *FileRequirerPaths {
	fr := &FileRequirerPaths{
		required: make(map[string]bool),
	}
	for _, r := range required {
		fr.required[r] = true
	}
	return fr
}

// FileRequired returns true if the file is required.
func (fr *FileRequirerPaths) FileRequired(path string, fileinfo fs.FileInfo) bool {
	return fr.required[path]
}
