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

// Package diriterate provides a utility for iterating over the contents of a directory without
// loading all of it into memory at once.
package diriterate

import (
	"errors"
	"io"
	"io/fs"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// ReadDir reads the named directory and returns an iterator over the directory entries.
func ReadDir(fsys scalibrfs.FS, name string) (*DirIterator, error) {
	// Check if the path is accessible
	_, err := fsys.Stat(name)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}

	// Try to open the directory
	file, err := fsys.Open(name)
	if err != nil {
		// The underlying filesystem might not have implemented Open() for directories.
		// In this case, we fall back to reading all entries using readDirAll()
		return readDirAll(fsys, name)
	}

	// Check if the file supports incremental Readdir
	dir, ok := file.(fs.ReadDirFile)
	if !ok {
		// If ReadDirFile is not implemented, close the file and fall back to reading all entries
		// (Uses more memory since it reads all subdirs at once.)
		if err := file.Close(); err != nil {
			return nil, &fs.PathError{Op: "close", Path: name, Err: err}
		}
		return readDirAll(fsys, name)
	}

	return &DirIterator{dir: dir}, nil
}

// readDirAll reads all directory entries using fsys.ReadDir
// and returns a DirIterator with preloaded entries.
func readDirAll(fsys scalibrfs.FS, name string) (*DirIterator, error) {
	files, err := fsys.ReadDir(name)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not implemented")}
	}
	return &DirIterator{files: files, curr: 0}, nil
}

// DirIterator iterates over the contents of a directory without loading all
// of it into memory at once.
type DirIterator struct {
	// dir is used to iterate directory entries
	dir fs.ReadDirFile
	// if dir doesn't implement fs.ReadDirFile, file and curr are used as
	// fallback to iterate through a preloaded list of files
	files []fs.DirEntry
	curr  int
}

// Next returns the next fs.DirEntry from the directory. If error is nil, there will be a
// fs.DirEntry returned.
func (i *DirIterator) Next() (fs.DirEntry, error) {
	if len(i.files) > 0 {
		if i.curr >= len(i.files) {
			return nil, io.EOF
		}
		i.curr++
		return i.files[i.curr-1], nil
	}

	if i.dir == nil {
		// This is an iterator for an empty directory, so we return EOF immediately.
		return nil, io.EOF
	}

	list, err := i.dir.ReadDir(1)
	if err != nil {
		return nil, err
	}

	return list[0], nil
}

// Close closes the directory file.
func (i *DirIterator) Close() error {
	if i.dir == nil {
		return nil
	}
	return i.dir.Close()
}
