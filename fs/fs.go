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
	fn func(fs.FS, string) (T, error),
) (T, error) {
	var res T
	err := r.withRoot(opName, name, func(root *os.Root) error {
		fsys := root.FS()
		var opErr error
		res, opErr = fn(fsys, name)
		if opErr == nil {
			return nil
		}
		if resolved, ok := resolve(root, name, opErr); ok {
			res, opErr = fn(fsys, resolved)
		}
		return opErr
	})
	return res, err
}

func (r *rootFS) Open(name string) (fs.File, error) {
	return doInRoot(r, "open", name, resolveInRoot, fs.FS.Open)
}

func (r *rootFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return doInRoot(r, "readdir", name, resolveInRoot, fs.ReadDir)
}

func (r *rootFS) Stat(name string) (fs.FileInfo, error) {
	return doInRoot(r, "stat", name, resolveInRoot, fs.Stat)
}

func (r *rootFS) ReadFile(name string) ([]byte, error) {
	return doInRoot(r, "open", name, resolveInRoot, fs.ReadFile)
}

func (r *rootFS) ReadLink(name string) (string, error) {
	return doInRoot(r, "readlink", name, resolveParentInRoot, fs.ReadLink)
}

func (r *rootFS) Lstat(name string) (fs.FileInfo, error) {
	return doInRoot(r, "lstat", name, resolveParentInRoot, fs.Lstat)
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
	if opErr == nil || !strings.Contains(opErr.Error(), "path escapes from parent") {
		return "", false
	}
	if !fs.ValidPath(name) || name == "." || (runtime.GOOS == "windows" && strings.ContainsRune(name, '\\')) {
		return "", false
	}
	remaining := strings.Split(name, "/")
	cur := "."
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
			if cur == "." {
				return "", false
			}
			cur = path.Dir(cur)
			continue
		}

		next := path.Join(cur, part)
		fi, err := root.Lstat(filepath.FromSlash(next))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && rewroteAbs && len(remaining) == 0 {
				return next, true
			}
			return "", false
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			curIsDir = fi.IsDir()
			continue
		}

		if hops++; hops > maxSymlinkDepth {
			return "", false
		}
		target, err := root.Readlink(filepath.FromSlash(next))
		if err != nil || filepath.VolumeName(target) != "" {
			return "", false
		}
		target = filepath.ToSlash(target)
		if after, ok := strings.CutPrefix(target, "/"); ok {
			rewroteAbs = true
			cur = "."
			curIsDir = true
			target = after
		}
		if target != "" {
			remaining = append(strings.Split(target, "/"), remaining...)
		}
	}

	if !rewroteAbs {
		return "", false
	}
	return cur, true
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

func openReader(root *ScanRoot, path string, reader io.Reader) (io.ReadCloser, error) {
	if root != nil {
		fsys := root.FS
		if fsys == nil && !root.IsVirtual() {
			// Fallback for unit tests that construct ScanInput with FS: nil.
			rfs := &rootFS{dir: root.Path}
			defer func() { _ = rfs.Close() }()
			fsys = rfs
		}
		if fsys != nil {
			f, err := fsys.Open(filepath.ToSlash(path))
			if err == nil {
				return f, nil
			}
			if !errors.Is(err, fs.ErrNotExist) || reader == nil {
				return nil, err
			}
		}
	}
	if reader == nil {
		return nil, errors.New("GetRealPath: both root.FS and reader are nil")
	}
	return io.NopCloser(reader), nil
}

func copyToTempFile(reader io.Reader) (realPath string, err error) {
	dir, err := os.MkdirTemp("", "scalibr-tmp")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()

	realPath = filepath.Join(dir, "file")
	f, err := os.Create(realPath)
	if err != nil {
		return "", err
	}
	if _, err = io.Copy(f, reader); err != nil {
		_ = f.Close()
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}

	return realPath, nil
}

func closeIgnoringClosed(f *os.File) error {
	if err := f.Close(); err != nil && !errors.Is(err, fs.ErrClosed) {
		return err
	}
	return nil
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
//	    log.Errorf("os.RemoveAll(%q): %v", dir, err)
//	}
func GetRealPath(root *ScanRoot, path string, reader io.Reader) (string, error) {
	rc, err := openReader(root, path, reader)
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	return copyToTempFile(rc)
}

// OpenOSFile returns an *os.File handle for the target file along with a cleanup function that
// closes the file and removes any temporary copy that had to be created. On real filesystems, it
// returns the *os.File opened directly from root.FS without copying the file to a temporary
// directory.
func OpenOSFile(root *ScanRoot, path string, reader io.Reader) (*os.File, func() error, error) {
	rc, err := openReader(root, path, reader)
	if err != nil {
		return nil, nil, err
	}
	if osFile, ok := rc.(*os.File); ok {
		return osFile, func() error { return closeIgnoringClosed(osFile) }, nil
	}
	realPath, copyErr := copyToTempFile(rc)
	_ = rc.Close()
	if copyErr != nil {
		return nil, nil, copyErr
	}
	dir := filepath.Dir(realPath)
	osFile, err := os.Open(realPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, err
	}
	cleanup := func() error {
		closeErr := closeIgnoringClosed(osFile)
		rmErr := os.RemoveAll(dir)
		return errors.Join(closeErr, rmErr)
	}
	return osFile, cleanup, nil
}
