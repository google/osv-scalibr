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
	"syscall"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
)

// maxSubRootDepth caps the number of simultaneously open child os.Root handles
// during recursive traversal so deep directory trees stay well within tight
// per-process file descriptor limits (such as macOS's default 256 soft limit,
// where each active DirIterator holds 2 FDs due to fdopendir duplication).
// If FD exhaustion still occurs (EMFILE/ENFILE), traversal falls back to the
// parent FS without failing the subtree.
const maxSubRootDepth = 32

type subFSOpener interface {
	OpenSubFS(name string) (scalibrfs.FS, error)
}

type postWalkDirFunc func(path string, d fs.DirEntry)

// NormalizePathError rewrites a top-level *fs.PathError's Path field to
// fullPath so callers see scan-root-relative paths rather than sub-root-relative
// paths, without stripping wrapped or joined error context.
func NormalizePathError(err error, fullPath string) error {
	//nolint:errorlint // Only rewrite a top-level *fs.PathError so wrapped/joined error context is preserved.
	if pe, ok := err.(*fs.PathError); ok && pe.Path != fullPath {
		return &fs.PathError{Op: pe.Op, Path: fullPath, Err: pe.Err}
	}
	return err
}

func isFDExhausted(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

func handleWalkErr(fullPath string, d fs.DirEntry, err error, walkDirFn fs.WalkDirFunc) error {
	err = walkDirFn(fullPath, d, NormalizePathError(err, fullPath))
	if err != nil {
		if errors.Is(err, fs.SkipDir) && d.IsDir() {
			return nil
		}
		return err
	}
	// End iteration after an error.
	return nil
}

// walkDirUnsorted recursively descends path, calling walkDirFn. From caller side this function
// should be equivalent to fs.walkDir, except that the files are not ordered, but walked in the
// order returned by the file system. This function does not store the full directory in memory,
// which should reduce the memory footprint from O(n) to O(1).
// This might lead to inconsistencies in the seen files, as another process might delete a file
// during the walk, which is then not seen by the walk. That problem existed also with fs.WalkDir,
// which would return files which do not exist anymore. More details for unix:
// https://man7.org/linux/man-pages/man2/getdents.2.html
func walkDirUnsorted(curFS scalibrfs.FS, fullPath, relPath string, depth int, d fs.DirEntry, walkDirFn fs.WalkDirFunc, postFN postWalkDirFunc) error {
	if postFN != nil {
		defer postFN(fullPath, d)
	}
	// This is the main call to walkDirFn for files and directories, without errors.
	if err := walkDirFn(fullPath, d, nil); err != nil || !d.IsDir() {
		if errors.Is(err, fs.SkipDir) && d.IsDir() {
			// Successfully skipped directory.
			err = nil
		}
		return err
	}

	// Open a confined child FS for this directory so children are opened relative
	// to the parent directory FD in O(1) instead of re-traversing from the root.
	parentFS, parentRelPath := curFS, relPath
	var (
		openedSubFS bool
		subCloser   io.Closer
	)
	if relPath != "." && depth < maxSubRootDepth {
		if opener, ok := curFS.(subFSOpener); ok {
			subFS, err := opener.OpenSubFS(relPath)
			if err == nil {
				openedSubFS = true
				if closer, ok := subFS.(io.Closer); ok {
					subCloser = closer
					defer func() {
						if subCloser != nil {
							_ = subCloser.Close()
						}
					}()
				}
				curFS = subFS
				relPath = "."
				depth++
			} else if !errors.Is(err, errors.ErrUnsupported) && !isFDExhausted(err) {
				return handleWalkErr(fullPath, d, err, walkDirFn)
			}
		}
	}

	dirs, err := diriterate.ReadDir(curFS, relPath)
	if err != nil && openedSubFS && isFDExhausted(err) {
		if subCloser != nil {
			_ = subCloser.Close()
			subCloser = nil
		}
		curFS = parentFS
		relPath = parentRelPath
		depth--
		dirs, err = diriterate.ReadDir(curFS, relPath)
	}
	if err != nil {
		return handleWalkErr(fullPath, d, err, walkDirFn)
	}
	// Error can be ignored, as no write is happening.
	defer func() { _ = dirs.Close() }()

	for {
		d1, err := dirs.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return handleWalkErr(fullPath, d, err, walkDirFn)
		}
		name1 := path.Join(fullPath, d1.Name())
		rel1 := path.Join(relPath, d1.Name())
		if err := walkDirUnsorted(curFS, name1, rel1, depth, d1, walkDirFn, postFN); err != nil {
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
		err = walkDirUnsorted(fsys, root, root, 0, fs.FileInfoToDirEntry(info), fn, postFN)
	}
	if errors.Is(err, fs.SkipDir) || errors.Is(err, fs.SkipAll) {
		return nil
	}
	return err
}
