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

// Package diriterate provides a utility for iterating over the contents of a directory without
// loading all of it into memory at once.
package diriterate

import (
	"errors"
	"io"
	"io/fs"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// readDirBatchSize caps how many directory entries DirIterator fetches per
// ReadDir call, amortizing per-call overhead while keeping memory O(1).
const readDirBatchSize = 64

type dirOpener interface {
	OpenDir(name string) (fs.ReadDirFile, error)
}

// ReadDir reads the named directory and returns an iterator over the directory entries.
func ReadDir(fsys scalibrfs.FS, name string) (*DirIterator, error) {
	if opener, ok := fsys.(dirOpener); ok {
		dir, err := opener.OpenDir(name)
		if err == nil {
			return &DirIterator{dir: dir}, nil
		}
		if !errors.Is(err, errors.ErrUnsupported) {
			return nil, err
		}
	}

	// Try to open the directory.
	file, openErr := fsys.Open(name)
	if openErr != nil {
		if errors.Is(openErr, fs.ErrNotExist) || errors.Is(openErr, fs.ErrPermission) {
			return nil, openErr
		}
		// The underlying filesystem might not implement Open() for directories.
		// Fall back to reading all entries via ReadDir(); if that also fails,
		// return the original Open error so callers see the real OS error.
		if it, err := readDirAll(fsys, name); err == nil {
			return it, nil
		}
		return nil, openErr
	}

	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: statErr}
	}
	if info != nil && !info.IsDir() {
		_ = file.Close()
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}

	// Check if the file supports incremental ReadDir.
	dir, ok := file.(fs.ReadDirFile)
	if !ok {
		// If ReadDirFile is not implemented, close the file and fall back to reading all entries
		// (uses more memory since it reads all subdirs at once).
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
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	return &DirIterator{files: files, curr: 0}, nil
}

// DirIterator iterates over the contents of a directory without loading all
// of it into memory at once.
type DirIterator struct {
	// dir is used to iterate directory entries in bounded batches.
	dir fs.ReadDirFile
	// files buffers either the current batch from dir or preloaded entries
	// from the readDirAll fallback.
	files []fs.DirEntry
	curr  int
	// err stores a deferred error returned alongside a non-empty final batch.
	err error
}

// Next returns the next fs.DirEntry from the directory. If error is nil, there will be a
// fs.DirEntry returned.
func (i *DirIterator) Next() (fs.DirEntry, error) {
	if i.curr < len(i.files) {
		entry := i.files[i.curr]
		i.curr++
		return entry, nil
	}
	if i.err != nil {
		return nil, i.err
	}
	if i.dir == nil {
		// This is an iterator for an empty or exhausted preloaded directory.
		return nil, io.EOF
	}

	list, err := i.dir.ReadDir(readDirBatchSize)
	i.files = list
	i.curr = 0
	i.err = err
	if len(list) > 0 {
		i.curr = 1
		return list[0], nil
	}
	if err != nil {
		return nil, err
	}
	i.err = io.EOF
	return nil, io.EOF
}

// Close closes the directory file.
func (i *DirIterator) Close() error {
	if i == nil || i.dir == nil {
		return nil
	}
	return i.dir.Close()
}
