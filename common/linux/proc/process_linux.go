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

//go:build linux

// Package proc provides utilities to parse /proc files.
package proc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

var (
	errReadDirFile = errors.New("internal error: failed to convert to fs.ReadDirFile")
)

type iterateFunc func(d fs.DirEntry) error

// ReadProcessCmdline returns the command line of a specific process identified by its PID.
func ReadProcessCmdline(ctx context.Context, pid int64, root string, fsys scalibrfs.FS) ([]string, error) {
	path := filepath.Join("proc", strconv.FormatInt(pid, 10), "cmdline")
	file, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cmdline, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	cmd := strings.Trim(string(cmdline), "\x00")
	return strings.Split(cmd, string('\x00')), nil
}

// MapSocketInodesToPID returns a map of mapped PID for all currently open sockets.
// Note that depending on permissions, not all sockets will be mapped.
// This function:
//   - walks the /proc directory
//   - filters to process only directories associated with a process
//   - for each process, it walks the /proc/<pid>/fd directory
//   - for each file descriptor, it checks if it is a socket and extracts its inode number
func MapSocketInodesToPID(ctx context.Context, root string, fsys scalibrfs.FS) (map[int64]int64, error) {
	inodesToPID := make(map[int64]int64)
	// For each entry in /proc, we try to read its descriptors and ignore permission errors.
	fn := func(d fs.DirEntry) error {
		if err := readFileDescriptors(ctx, d, inodesToPID, root, fsys); err != nil {
			if !errors.Is(err, fs.ErrPermission) {
				return err
			}
		}

		return nil
	}

	if err := iterateDirectory(ctx, "proc", fsys, fn); err != nil {
		return nil, err
	}

	return inodesToPID, nil
}

func readFileDescriptors(ctx context.Context, d fs.DirEntry, inodesToPID map[int64]int64, root string, fsys scalibrfs.FS) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if !d.IsDir() {
		return nil
	}

	// only read PID directories
	pid, err := strconv.ParseInt(d.Name(), 10, 64)
	if err != nil {
		return nil
	}

	fdPath := filepath.Join("proc", d.Name(), "fd")
	absFdPath := filepath.Join(root, fdPath)
	// for each file descriptor in the process directory, we try to extract the inode number for
	// sockets.
	fn := func(d fs.DirEntry) error {
		inode, err := extractSocketInode(ctx, absFdPath, d)
		if err != nil {
			return err
		}

		if inode != 0 {
			inodesToPID[inode] = pid
		}

		return nil
	}

	if err := iterateDirectory(ctx, fdPath, fsys, fn); err != nil {
		return err
	}

	return nil
}

func extractSocketInode(ctx context.Context, absFdDir string, d fs.DirEntry) (int64, error) {
	if d.Type() != fs.ModeSymlink {
		return 0, nil
	}

	link, err := os.Readlink(filepath.Join(absFdDir, d.Name()))
	if err != nil {
		return 0, err
	}

	if !strings.Contains(link, "socket:") {
		return 0, nil
	}

	var inode int64
	if _, err := fmt.Sscanf(link, "socket:[%d]", &inode); err != nil {
		return 0, nil
	}

	return inode, nil
}

// iterateDirectory iterates over entries of a directory and applies fn() to each entry.
func iterateDirectory(ctx context.Context, path string, fsys scalibrfs.FS, fn iterateFunc) error {
	f, err := fsys.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	rd, ok := f.(fs.ReadDirFile)
	if !ok {
		return errReadDirFile
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		entries, err := rd.ReadDir(1)
		if err != nil {
			if err == io.EOF {
				break
			}

			return err
		}

		if err := fn(entries[0]); err != nil {
			return err
		}
	}

	return nil
}
