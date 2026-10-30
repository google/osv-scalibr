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

// Package fs provides a virtual filesystem interface for SCALIBR scans and related helper functions.
package fs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// FS is a filesystem interface that allows the opening of files, reading of
// directories, and performing stat on files.
//
// FS implementations may return ErrNotImplemented for `Open`, `ReadDir` and `Stat`.
// Extractor implementations must decide whether the error is fatal or can be ignored.
//
// FS implementations MUST implement io.ReaderAt for opened files to enable random access.
type FS interface {
	fs.FS
	fs.ReadDirFS
	fs.StatFS
}

// ScanRoot defines a root directory to start a scan from.
// mounted to a local dir.
type ScanRoot struct {
	// A virtual filesystem for file access, rooted at the scan root.
	FS FS
	// The path of the scan root. Empty if this is a virtual filesystem and the
	// scanning environment doesn't support the DirectFS requirement.
	Path string
}

// IsVirtual returns true if the scan root represents the root of a virtual
// filesystem, i.e. one with no real location on the disk of the scanned host.
func (r *ScanRoot) IsVirtual() bool {
	return r.Path == ""
}

// WithAbsolutePath returns a copy of the ScanRoot with the Path
// set an absolute path.
func (r *ScanRoot) WithAbsolutePath() (*ScanRoot, error) {
	if r.Path == "" {
		// Virtual-only filesystem
		return &ScanRoot{FS: r.FS, Path: r.Path}, nil
	}
	absroot, err := filepath.Abs(r.Path)
	if err != nil {
		return nil, err
	}
	return &ScanRoot{FS: r.FS, Path: absroot}, nil
}

const maxSymlinkDepth = 40

// DirFS returns an FS implementation that accesses the real filesystem at the
// given root, confined to root via os.Root. The underlying os.Root handle is
// opened lazily on first access and can be released via Close.
func DirFS(root string) FS {
	return &rootFS{dir: root}
}

type rootFS struct {
	dir  string
	mu   sync.Mutex
	root *os.Root
}

func (r *rootFS) getRoot() (*os.Root, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.root != nil {
		return r.root, nil
	}
	root, err := os.OpenRoot(r.dir)
	if err != nil {
		return nil, err
	}
	r.root = root
	return root, nil
}

func (r *rootFS) withRoot(op, name string, fn func(*os.Root) error) error {
	if r.dir == "" {
		return &fs.PathError{Op: op, Path: name, Err: errors.New("os: DirFS with empty root")}
	}
	if runtime.GOOS == "windows" {
		root, err := os.OpenRoot(r.dir)
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		return fn(root)
	}
	root, err := r.getRoot()
	if err != nil {
		return err
	}
	return fn(root)
}

// Close releases the underlying os.Root file descriptor if one was opened.
func (r *rootFS) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.root == nil {
		return nil
	}
	err := r.root.Close()
	r.root = nil
	return err
}

func doInRoot[T any](
	r *rootFS,
	opName, name string,
	resolve func(*os.Root, string, error) (string, bool),
	fn func(*os.Root, string) (T, error),
) (T, error) {
	var res T
	err := r.withRoot(opName, name, func(root *os.Root) error {
		var opErr error
		res, opErr = fn(root, name)
		if opErr == nil {
			return nil
		}
		if resolved, ok := resolve(root, name, opErr); ok {
			res, opErr = fn(root, resolved)
		}
		return opErr
	})
	return res, err
}

func (r *rootFS) Open(name string) (fs.File, error) {
	f, err := doInRoot(r, "open", name, resolveInRoot, func(root *os.Root, p string) (fs.File, error) {
		return root.FS().Open(p)
	})
	return f, err
}

func (r *rootFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := doInRoot(r, "readdir", name, resolveInRoot, func(root *os.Root, p string) ([]fs.DirEntry, error) {
		return root.FS().(fs.ReadDirFS).ReadDir(p)
	})
	return entries, err
}

func (r *rootFS) Stat(name string) (fs.FileInfo, error) {
	info, err := doInRoot(r, "stat", name, resolveInRoot, func(root *os.Root, p string) (fs.FileInfo, error) {
		return root.FS().(fs.StatFS).Stat(p)
	})
	return info, err
}

func (r *rootFS) ReadFile(name string) ([]byte, error) {
	b, err := doInRoot(r, "open", name, resolveInRoot, func(root *os.Root, p string) ([]byte, error) {
		return root.FS().(fs.ReadFileFS).ReadFile(p)
	})
	return b, err
}

func (r *rootFS) ReadLink(name string) (string, error) {
	return doInRoot(r, "readlink", name, resolveParentInRoot, func(root *os.Root, p string) (string, error) {
		return root.FS().(fs.ReadLinkFS).ReadLink(p)
	})
}

func (r *rootFS) Lstat(name string) (fs.FileInfo, error) {
	return doInRoot(r, "lstat", name, resolveParentInRoot, func(root *os.Root, p string) (fs.FileInfo, error) {
		return root.FS().(fs.ReadLinkFS).Lstat(p)
	})
}

func resolveParentInRoot(root *os.Root, name string, opErr error) (string, bool) {
	if !fs.ValidPath(name) {
		return "", false
	}
	dir := path.Dir(name)
	if dir == "." {
		return "", false
	}
	resolvedDir, ok := resolveInRoot(root, dir, opErr)
	if !ok {
		return "", false
	}
	return path.Join(resolvedDir, path.Base(name)), true
}

// resolveInRoot resolves intra-root absolute symlinks (such as
// /etc/os-release -> /usr/lib/os-release in guest container/VM rootfses)
// relative to root, up to maxSymlinkDepth hops. It returns true only if at
// least one absolute symlink was rewritten into a valid root-relative path.
func resolveInRoot(root *os.Root, name string, opErr error) (string, bool) {
	if opErr != nil && (errors.Is(opErr, fs.ErrNotExist) || errors.Is(opErr, fs.ErrInvalid)) {
		return "", false
	}
	if !fs.ValidPath(name) || name == "." || (runtime.GOOS == "windows" && strings.ContainsRune(name, '\\')) {
		return "", false
	}
	remaining := strings.Split(name, "/")
	cur := ""
	curIsDir := true
	hops := 0
	rewroteAbs := false

	for len(remaining) > 0 {
		part := remaining[0]
		remaining = remaining[1:]
		if !curIsDir {
			return "", false
		}
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if cur == "" {
				return "", false
			}
			if idx := strings.LastIndexByte(cur, '/'); idx >= 0 {
				cur = cur[:idx]
			} else {
				cur = ""
			}
			continue
		}

		next := part
		if cur != "" {
			next = cur + "/" + part
		}
		fi, err := root.Lstat(filepath.FromSlash(next))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && rewroteAbs && cur != "" && len(remaining) == 0 {
				return next, fs.ValidPath(next)
			}
			return "", false
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			curIsDir = fi.IsDir()
			continue
		}

		hops++
		if hops > maxSymlinkDepth {
			return "", false
		}
		target, err := root.Readlink(filepath.FromSlash(next))
		if err != nil || filepath.VolumeName(target) != "" {
			return "", false
		}
		target = filepath.ToSlash(target)
		if strings.HasPrefix(target, "/") {
			rewroteAbs = true
			cur = ""
			curIsDir = true
			if trimmed := strings.TrimLeft(target, "/"); trimmed != "" {
				remaining = append(strings.Split(trimmed, "/"), remaining...)
			}
		} else if target != "" {
			remaining = append(strings.Split(target, "/"), remaining...)
		}
	}

	if !rewroteAbs {
		return "", false
	}
	if cur == "" {
		cur = "."
	}
	return cur, fs.ValidPath(cur)
}

// Sub returns an FS corresponding to the subtree rooted at dir within fsys.
// This is analogous to io/fs.Sub but preserves the scalibr FS interface
// (ReadDir and Stat). dir must be a slash-separated, relative path. The
// returned FS performs no validation of the names it is given, so it should
// only be used with trusted paths.
func Sub(fsys FS, dir string) FS {
	if dir == "" || dir == "." {
		return fsys
	}
	return &subFS{fsys: fsys, dir: dir}
}

type subFS struct {
	fsys FS
	dir  string
}

func (s *subFS) Open(name string) (fs.File, error) {
	return s.fsys.Open(path.Join(s.dir, name))
}

func (s *subFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return s.fsys.ReadDir(path.Join(s.dir, name))
}

func (s *subFS) Stat(name string) (fs.FileInfo, error) {
	return s.fsys.Stat(path.Join(s.dir, name))
}

// RealFSScanRoots returns a one-element ScanRoot array representing the given
// root path on the real filesystem SCALIBR is running on.
func RealFSScanRoots(path string) []*ScanRoot {
	return []*ScanRoot{RealFSScanRoot(path)}
}

// RealFSScanRoot returns a ScanRoot array the given root path on the real
// filesystem SCALIBR is running on.
func RealFSScanRoot(path string) *ScanRoot {
	return &ScanRoot{FS: DirFS(path), Path: path}
}

// NewReaderAt converts an io.Reader into an io.ReaderAt.
func NewReaderAt(ioReader io.Reader) (io.ReaderAt, error) {
	r, ok := ioReader.(io.ReaderAt)
	if ok {
		return r, nil
	}

	// Fallback: In case ioReader does not implement ReadAt, we use a reader on byte buffer
	// instead, which supports ReadAt. Note that in this case the whole file contents will be
	// loaded into memory which might be expensive for large files.
	buff := bytes.NewBuffer([]byte{})
	_, err := io.Copy(buff, ioReader)
	if err != nil {
		return nil, fmt.Errorf("io.Copy(): %w", err)
	}

	return bytes.NewReader(buff.Bytes()), nil
}

// GetRealPath copies the file into an isolated temporary directory on the scanning host's
// filesystem and returns its absolute path. It is up to the caller to delete the temporary
// directory (filepath.Dir(realPath)) once they are done using it.
//
// Sample code to delete the directory:
// ```
// realPath := GetRealPath(...)
// dir := filepath.Dir(realPath)
//
//	if err := os.RemoveAll(dir); err != nil {
//	    log.Errorf("os.RemoveAll(%q): %w", dir, err)
//	}
func GetRealPath(root *ScanRoot, path string, reader io.Reader) (string, error) {
	if root != nil {
		fsys := root.FS
		if fsys == nil && !root.IsVirtual() {
			// Fallback for unit tests that construct ScanInput with FS: nil.
			fsys = DirFS(root.Path)
			if c, ok := fsys.(io.Closer); ok {
				defer c.Close()
			}
		}
		if fsys != nil {
			f, err := fsys.Open(filepath.ToSlash(path))
			if err == nil {
				defer f.Close()
				reader = f
			} else if !errors.Is(err, fs.ErrNotExist) || reader == nil {
				return "", err
			}
		}
	}
	if reader == nil {
		return "", errors.New("GetRealPath: both root.FS and reader are nil")
	}

	dir, err := os.MkdirTemp("", "scalibr-tmp")
	if err != nil {
		return "", err
	}
	realPath := filepath.Join(dir, "file")
	f, err := os.Create(realPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if _, err := io.Copy(f, reader); err != nil {
		_ = f.Close()
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}

	return realPath, nil
}
