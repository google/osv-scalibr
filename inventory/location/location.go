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

// Package location provides structs for storing the location of inventory items found (e.g. packages or secrets).
package location

// Location is the location for an Inventory item found on the
// scanned artifact (e.g. a software package or a secret).
type Location struct {
	File *File
}

// File is a file-based location.
type File struct {
	Path string
	// Specific position of the inventory item inside the file.
	LineNumber int
}

// FromPath returns a Location struct based on a file path.
func FromPath(path string) Location {
	return Location{File: &File{Path: path}}
}

// PathOrEmpty returns the path of the location
// or an empty string if the location is not a file path.
func (l *Location) PathOrEmpty() string {
	if l == nil || l.File == nil {
		return ""
	}
	return l.File.Path
}
