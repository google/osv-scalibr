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

//go:build unix && go1.26

package fs

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"syscall"
)

// OpenDir opens name for streaming directory reads while preserving os.Root
// confinement. On Unix, Go's os.Root.Open marks returned *os.File handles as
// inRoot, forcing per-entry fstatat syscalls during ReadDir instead of using
// getdents/getdirentries d_type. Duplicating the already-confined directory FD
// via os.NewFile re-enables d_type fast paths, while confinedDirEntry ensures
// DirEntry.Info() still uses root.Lstat instead of unconfined os.Lstat.
// Entries returned by ReadDir require the underlying rootFS to remain open
// when calling Info.
func (r *rootFS) OpenDir(name string) (fs.ReadDirFile, error) {
	if !validRelPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	var (
		f            *os.File
		rootRef      *os.Root
		resolvedName = name
	)
	err := r.withRoot("open", name, func(root *os.Root) error {
		rootRef = root
		var opErr error
		f, opErr = root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if opErr == nil {
			return nil
		}
		if !r.inSubdir {
			if resolved, ok := resolveInRoot(root, name, opErr); ok {
				resolvedName = resolved
				f, opErr = root.OpenFile(resolved, os.O_RDONLY|syscall.O_DIRECTORY, 0)
			}
		}
		return opErr
	})
	if err != nil {
		return nil, err
	}

	dupFile, dupErr := dupDirFile(f, name)
	_ = f.Close()
	if dupErr != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: dupErr}
	}
	return &confinedReadDirFile{
		file:    dupFile,
		root:    rootRef,
		relDir:  resolvedName,
		origDir: name,
	}, nil
}

func dupDirFile(f *os.File, name string) (*os.File, error) {
	rawConn, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var dupFD int
	var dupErr error
	if err := rawConn.Control(func(fd uintptr) {
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()
		for {
			dupFD, dupErr = syscall.Dup(int(fd))
			if !errors.Is(dupErr, syscall.EINTR) {
				break
			}
		}
		if dupErr == nil {
			syscall.CloseOnExec(dupFD)
		}
	}); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	dupFile := os.NewFile(uintptr(dupFD), name)
	if dupFile == nil {
		_ = syscall.Close(dupFD)
		return nil, errors.New("os.NewFile returned nil")
	}
	return dupFile, nil
}

type confinedReadDirFile struct {
	file    *os.File
	root    *os.Root
	relDir  string
	origDir string
}

func (c *confinedReadDirFile) Stat() (fs.FileInfo, error) {
	return c.file.Stat()
}

func (c *confinedReadDirFile) Read(b []byte) (int, error) {
	return c.file.Read(b)
}

func (c *confinedReadDirFile) Close() error {
	return c.file.Close()
}

func (c *confinedReadDirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := c.file.ReadDir(n)
	if len(entries) == 0 {
		return entries, err
	}
	// Allocate all wrappers in one contiguous slice and reuse entries in place
	// to avoid a per-entry heap allocation when boxing into fs.DirEntry.
	batch := make([]confinedDirEntry, len(entries))
	for i, e := range entries {
		batch[i] = confinedDirEntry{
			entry:   e,
			root:    c.root,
			relDir:  c.relDir,
			origDir: c.origDir,
		}
		entries[i] = &batch[i]
	}
	return entries, err
}

type confinedDirEntry struct {
	entry   fs.DirEntry
	root    *os.Root
	relDir  string
	origDir string
}

func (c *confinedDirEntry) Name() string      { return c.entry.Name() }
func (c *confinedDirEntry) IsDir() bool       { return c.entry.IsDir() }
func (c *confinedDirEntry) Type() fs.FileMode { return c.entry.Type() }
func (c *confinedDirEntry) String() string    { return fs.FormatDirEntry(c) }

func (c *confinedDirEntry) Info() (fs.FileInfo, error) {
	info, err := c.root.Lstat(path.Join(c.relDir, c.entry.Name()))
	if err != nil && c.origDir != c.relDir {
		return nil, normalizePathError("lstat", path.Join(c.origDir, c.entry.Name()), err)
	}
	return info, err
}
