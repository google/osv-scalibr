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

package internal

// Derived from Go's src/io/fs/walk.go
//
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import (
	"errors"
	"io"
	"io/fs"
	"path"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
)

type postWalkDirFunc func(path string, d fs.DirEntry)

// walkDirUnsorted recursively descends path, calling walkDirFn. From caller side this function
// should be equivalent to fs.walkDir, except that the files are not ordered, but walked in the
// order returned by the file system. This function does not store the full directory in memory,
// which should reduce the memory footprint from O(n) to O(1).
// This might lead to inconsistencies in the seen files, as another process might delete a file
// during the walk, which is then not seen by the walk. That problem existed also with fs.WalkDir,
// which would return files which do not exist anymore. More details for unix:
// https://man7.org/linux/man-pages/man2/getdents.2.html
func walkDirUnsorted(fsys scalibrfs.FS, name string, d fs.DirEntry, walkDirFn fs.WalkDirFunc, postFN postWalkDirFunc) error {
	if postFN != nil {
		defer postFN(name, d)
	}
	// This is the main call to walkDirFn for files and directories, without errors.
	if err := walkDirFn(name, d, nil); err != nil || !d.IsDir() {
		if errors.Is(err, fs.SkipDir) && d.IsDir() {
			// Successfully skipped directory.
			err = nil
		}
		return err
	}

	dirs, err := diriterate.ReadDir(fsys, name)
	if err != nil {
		// Second call, to report ReadDir error.
		// Same error handling as in fs.WalkDir: If an error occurred, the walkDirFn is called again,
		// which can decide to continue (nil), SkipDir or skip all by other errors (e.g. SkipAll).
		err = walkDirFn(name, d, err)
		if err != nil {
			if errors.Is(err, fs.SkipDir) && d.IsDir() {
				err = nil
			}
			return err
		}
		// End iteration after an error
		return nil
	}
	// Error can be ignored, as no write is happening.
	defer dirs.Close()

	for {
		d1, err := dirs.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Second call, to report ReadDir error.
			// Same error handling as in fs.WalkDir: If an error occurred, the walkDirFn is called again,
			// which can decide to continue (nil), SkipDir or skip all by other errors (e.g. SkipAll).
			err = walkDirFn(name, d, err)
			if err != nil {
				if errors.Is(err, fs.SkipDir) && d.IsDir() {
					err = nil
				}
				return err
			}
			// End iteration after an error
			return nil
		}
		name1 := path.Join(name, d1.Name())
		if err := walkDirUnsorted(fsys, name1, d1, walkDirFn, postFN); err != nil {
			if errors.Is(err, fs.SkipDir) {
				break
			}
			return err
		}
	}
	return nil
}

// WalkDirUnsorted walks the file tree rooted at root, calling fn for each file or
// directory in the tree, including root. It also calls postFN after the walk of the
// file or dir has finished, including the traversal of all sub-directories.
//
// All errors that arise visiting files and directories are filtered by fn:
// see the [fs.WalkDirFunc] documentation for details.
//
// WalkDirUnsorted does not follow symbolic links found in directories,
// but if root itself is a symbolic link, its target will be walked.
func WalkDirUnsorted(fsys scalibrfs.FS, root string, fn fs.WalkDirFunc, postFN postWalkDirFunc) error {
	info, err := fs.Stat(fsys, root)
	if err != nil {
		err = fn(root, nil, err)
	} else {
		err = walkDirUnsorted(fsys, root, fs.FileInfoToDirEntry(info), fn, postFN)
	}
	if errors.Is(err, fs.SkipDir) || errors.Is(err, fs.SkipAll) {
		return nil
	}
	return err
}
