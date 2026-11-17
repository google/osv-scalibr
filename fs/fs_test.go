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

package fs_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestSub(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "chroot", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "chroot", "etc", "os-release"), []byte("ID=debian\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outer"), []byte("outer\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	base := scalibrfs.DirFS(root)
	t.Cleanup(func() {
		if c, ok := base.(io.Closer); ok {
			_ = c.Close()
		}
	})
	sub := scalibrfs.Sub(base, "chroot")

	// Open resolves relative to the sub-root.
	f, err := sub.Open("etc/os-release")
	if err != nil {
		t.Fatalf("Open(etc/os-release): %v", err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if want := "ID=debian\n"; string(got) != want {
		t.Errorf("Open(etc/os-release) = %q, want %q", got, want)
	}

	// Stat resolves relative to the sub-root.
	if _, err := sub.Stat("etc"); err != nil {
		t.Errorf("Stat(etc): %v", err)
	}

	// ReadDir resolves relative to the sub-root.
	entries, err := sub.ReadDir("etc")
	if err != nil {
		t.Fatalf("ReadDir(etc): %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "os-release" {
		t.Errorf("ReadDir(etc) = %v, want [os-release]", entries)
	}

	// Files outside the sub-root are not visible.
	if _, err := sub.Stat("outer"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(outer) err = %v, want fs.ErrNotExist", err)
	}
}

func TestSubEmptyDir(t *testing.T) {
	base := scalibrfs.DirFS(t.TempDir())
	t.Cleanup(func() {
		if c, ok := base.(io.Closer); ok {
			_ = c.Close()
		}
	})
	for _, dir := range []string{"", "."} {
		if got := scalibrfs.Sub(base, dir); got != base {
			t.Errorf("Sub(base, %q) returned a new FS, want the original", dir)
		}
	}
}

func TestDirFS_Unconfined(t *testing.T) {
	// DirFS("") returns a non-ErrNotExist error.
	emptyFS := scalibrfs.DirFS("")
	if _, err := emptyFS.Stat("any"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("DirFS(\"\").Stat(any) = %v, want non-ErrNotExist error", err)
	}

	parent := t.TempDir()
	root := filepath.Join(parent, "hostroot")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	roots := scalibrfs.RealFSScanRoots(root)
	if len(roots) != 1 || roots[0].Path != root {
		t.Fatalf("RealFSScanRoots(%q) = %v, want single root", root, roots)
	}
	fsys := roots[0].FS
	b, err := fs.ReadFile(fsys, "hello.txt")
	if err != nil {
		t.Fatalf("ReadFile(hello.txt): %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("ReadFile(hello.txt) = %q, want %q", b, "hello")
	}
	if _, err := fsys.Open("../outside"); err == nil {
		t.Errorf("Open(../outside) succeeded, want invalid path error")
	}

	if runtime.GOOS != "windows" {
		target := filepath.Join(parent, "target.txt")
		if err := os.WriteFile(target, []byte("linked"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "host-link.txt")); err != nil {
			t.Fatal(err)
		}
		got, err := fs.ReadFile(fsys, "host-link.txt")
		if err != nil {
			t.Fatalf("ReadFile(host-link.txt) on unconfined DirFS: %v", err)
		}
		if string(got) != "linked" {
			t.Errorf("ReadFile(host-link.txt) = %q, want %q", got, "linked")
		}
	}
}

func TestConfinedDirFS_LazyAndClose(t *testing.T) {
	// ConfinedDirFS("") returns a non-ErrNotExist error matching os.DirFS("").
	emptyFS := scalibrfs.ConfinedDirFS("")
	if _, err := emptyFS.Stat("any"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ConfinedDirFS(\"\").Stat(any) = %v, want non-ErrNotExist error", err)
	}

	// ConfinedDirFS must not open the directory eagerly so callers can construct
	// ScanRoot configs with placeholder paths before running a scan.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	lazyFS := scalibrfs.ConfinedDirFS(missing)
	if _, err := lazyFS.Stat("."); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(.) on missing root = %v, want fs.ErrNotExist", err)
	}

	dir := filepath.Join(t.TempDir(), "closeable")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	roots := scalibrfs.ConfinedScanRoots(dir)
	if len(roots) != 1 || roots[0].Path != dir {
		t.Fatalf("ConfinedScanRoots(%q) = %v, want single root", dir, roots)
	}
	fsys := roots[0].FS
	b, err := fs.ReadFile(fsys, "hello.txt")
	if err != nil {
		t.Fatalf("ReadFile(hello.txt): %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("ReadFile(hello.txt) = %q, want %q", b, "hello")
	}

	closer, ok := fsys.(io.Closer)
	if !ok {
		t.Fatal("ConfinedDirFS does not implement io.Closer")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	// Closing a second time is a no-op.
	if err := closer.Close(); err != nil {
		t.Fatalf("second Close(): %v", err)
	}
	// After Close(), the directory handle is released and can be removed on all OSes.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("os.RemoveAll(%q) after Close(): %v", dir, err)
	}
	if _, err := fsys.Open("hello.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open(hello.txt) after RemoveAll = %v, want fs.ErrNotExist", err)
	}
}

func TestConfinedDirFS_Symlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}

	parent := t.TempDir()
	outsideFile := filepath.Join(parent, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("host-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(parent, "rootfs")
	for _, d := range []string{"etc", "usr/lib", "usr/lib64", "app", "sub"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "lib", "os-release"), []byte("ID=guest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "lib64", "libc.so.6"), []byte("elf"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Intra-root relative and absolute symlinks.
	if err := os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc", "rel-os-release")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/os-release", filepath.Join(root, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib64", filepath.Join(root, "lib64")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libc.so.6", filepath.Join(root, "usr", "lib64", "libc.so")); err != nil {
		t.Fatal(err)
	}

	// Escaping symlinks and loops.
	if err := os.Symlink("../../outside.txt", filepath.Join(root, "app", "rel-escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(root, "app", "abs-escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside.txt", filepath.Join(root, "sub", "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/sub/escape", filepath.Join(root, "app", "chain-escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/b", filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/a", filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}

	fsys := scalibrfs.ConfinedDirFS(root)
	t.Cleanup(func() {
		if c, ok := fsys.(io.Closer); ok {
			_ = c.Close()
		}
	})

	tests := []struct {
		name        string
		path        string
		wantContent string
		wantErr     bool
	}{
		{
			name:        "relative_symlink_inside_root",
			path:        "etc/rel-os-release",
			wantContent: "ID=guest\n",
		},
		{
			name:        "intra_guest_absolute_symlink",
			path:        "etc/os-release",
			wantContent: "ID=guest\n",
		},
		{
			name:        "intra_guest_absolute_dir_symlink",
			path:        "lib64/libc.so.6",
			wantContent: "elf",
		},
		{
			name:    "relative_symlink_escape",
			path:    "app/rel-escape",
			wantErr: true,
		},
		{
			name:    "absolute_symlink_escape",
			path:    "app/abs-escape",
			wantErr: true,
		},
		{
			name:    "chained_abs_then_relative_escape",
			path:    "app/chain-escape",
			wantErr: true,
		},
		{
			name:    "symlink_loop",
			path:    "a",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := fsys.Open(tc.path)
			if tc.wantErr {
				if err == nil {
					_ = f.Close()
					t.Fatalf("Open(%q) succeeded, want error", tc.path)
				}
				if _, err := fsys.Stat(tc.path); err == nil {
					t.Errorf("Stat(%q) succeeded, want error", tc.path)
				}
				if _, err := fs.ReadFile(fsys, tc.path); err == nil {
					t.Errorf("ReadFile(%q) succeeded, want error", tc.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open(%q): %v", tc.path, err)
			}
			defer f.Close()
			got, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("ReadAll(%q): %v", tc.path, err)
			}
			if string(got) != tc.wantContent {
				t.Errorf("Open(%q) = %q, want %q", tc.path, got, tc.wantContent)
			}
			if _, err := fsys.Stat(tc.path); err != nil {
				t.Errorf("Stat(%q): %v", tc.path, err)
			}
			readGot, err := fs.ReadFile(fsys, tc.path)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", tc.path, err)
			}
			if string(readGot) != tc.wantContent {
				t.Errorf("ReadFile(%q) = %q, want %q", tc.path, readGot, tc.wantContent)
			}
		})
	}

	// Verify ReadDir, Lstat, and ReadLink across intra-guest absolute directory symlinks.
	entries, err := fsys.ReadDir("lib64")
	if err != nil {
		t.Fatalf("ReadDir(lib64): %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("ReadDir(lib64) len = %d, want 2", len(entries))
	}
	linfo, err := fs.Lstat(fsys, "lib64/libc.so")
	if err != nil {
		t.Fatalf("Lstat(lib64/libc.so): %v", err)
	}
	if linfo.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("Lstat(lib64/libc.so) mode = %v, want symlink", linfo.Mode())
	}
	target, err := fs.ReadLink(fsys, "lib64/libc.so")
	if err != nil {
		t.Fatalf("ReadLink(lib64/libc.so): %v", err)
	}
	if target != "libc.so.6" {
		t.Errorf("ReadLink(lib64/libc.so) = %q, want %q", target, "libc.so.6")
	}
	if _, err := fs.Lstat(fsys, "lib64/."); err == nil {
		t.Errorf("Lstat(lib64/.) = nil, want invalid path error")
	}
	if _, err := fs.ReadLink(fsys, "lib64/.."); err == nil {
		t.Errorf("ReadLink(lib64/..) = nil, want invalid path error")
	}
	if err := os.Symlink("/usr/lib/os-release/../os-release", filepath.Join(root, "etc", "file-dotdot")); err != nil {
		t.Fatal(err)
	}
	if f, err := fsys.Open("etc/file-dotdot"); err == nil {
		_ = f.Close()
		t.Errorf("Open(etc/file-dotdot) = nil, want error when traversing .. through regular file")
	}
	for _, linkName := range []string{"file-slash", "file-dot"} {
		targetPath := "/usr/lib/os-release/"
		if linkName == "file-dot" {
			targetPath = "/usr/lib/os-release/."
		}
		if err := os.Symlink(targetPath, filepath.Join(root, "etc", linkName)); err != nil {
			t.Fatal(err)
		}
		if f, err := fsys.Open("etc/" + linkName); err == nil {
			_ = f.Close()
			t.Errorf("Open(etc/%s) = nil, want error when traversing trailing slash/dot on regular file", linkName)
		}
	}
	if err := os.Symlink("/usr/lib/missing-os-release", filepath.Join(root, "etc", "dangling-os-release")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/missing-root-file", filepath.Join(root, "top-dangling")); err != nil {
		t.Fatal(err)
	}
	for _, missingPath := range []string{"etc/dangling-os-release", "top-dangling", "lib64/missing.so"} {
		if _, err := fsys.Open(missingPath); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Open(%q) = %v, want fs.ErrNotExist", missingPath, err)
		}
		if _, err := fsys.Stat(missingPath); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) = %v, want fs.ErrNotExist", missingPath, err)
		}
		if _, err := fs.ReadFile(fsys, missingPath); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("ReadFile(%q) = %v, want fs.ErrNotExist", missingPath, err)
		}
	}
}

// TestOSRootPathEscapesError guards the unexported os.errPathEscapes error
// text ("path escapes from parent") matched by resolveInRoot so any upstream
// Go stdlib change to src/os/root.go fails unit tests immediately on all OSes.
func TestOSRootPathEscapesError(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("os.OpenRoot: %v", err)
	}
	defer root.Close()

	_, err = root.Open("../outside")
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || pathErr.Err == nil || pathErr.Err.Error() != "path escapes from parent" {
		t.Fatalf("root.Open(../outside) err = %v, want *fs.PathError with Err %q", err, "path escapes from parent")
	}
}

func TestGetRealPath(t *testing.T) {
	rootDir := t.TempDir()
	content := "MZ-full-binary-content"
	if err := os.WriteFile(filepath.Join(rootDir, "app.dll"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "app.dll-wal"), []byte("sibling"), 0o644); err != nil {
		t.Fatal(err)
	}

	realScanRoot := scalibrfs.RealFSScanRoot(rootDir)
	confinedScanRoot := scalibrfs.ConfinedScanRoot(rootDir)
	t.Cleanup(func() {
		if c, ok := confinedScanRoot.FS.(io.Closer); ok {
			_ = c.Close()
		}
	})

	for _, tc := range []struct {
		name     string
		root     *scalibrfs.ScanRoot
		confined bool
	}{
		{name: "with_real_scan_root", root: realScanRoot, confined: false},
		{name: "with_confined_scan_root", root: confinedScanRoot, confined: true},
		{name: "with_nil_scan_root_fs", root: &scalibrfs.ScanRoot{Path: rootDir}, confined: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Pass a partially consumed reader to verify GetRealPath opens a fresh stream.
			partialReader := bytes.NewReader([]byte(content[2:]))
			realPath, err := scalibrfs.GetRealPath(tc.root, "app.dll", partialReader)
			if err != nil {
				t.Fatalf("GetRealPath(app.dll): %v", err)
			}
			t.Cleanup(func() {
				_ = os.RemoveAll(filepath.Dir(realPath))
			})

			if filepath.Dir(realPath) == rootDir {
				t.Errorf("GetRealPath returned in-place path %q inside rootDir %q, want isolated temp dir", realPath, rootDir)
			}
			got, err := os.ReadFile(realPath)
			if err != nil {
				t.Fatalf("os.ReadFile(%q): %v", realPath, err)
			}
			if string(got) != content {
				t.Errorf("GetRealPath file content = %q, want %q", got, content)
			}
			if _, err := os.Stat(realPath + "-wal"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("sibling -wal file exists next to %q: %v", realPath, err)
			}
			if tc.confined && runtime.GOOS != "windows" {
				outside := filepath.Join(t.TempDir(), "outside.dll")
				if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
					t.Fatal(err)
				}
				escapeLink := filepath.Join(rootDir, "escape-"+tc.name+".dll")
				if err := os.Symlink(outside, escapeLink); err != nil {
					t.Fatal(err)
				}
				dummyReader := bytes.NewReader([]byte("dummy"))
				if p, err := scalibrfs.GetRealPath(tc.root, filepath.Base(escapeLink), dummyReader); err == nil {
					_ = os.RemoveAll(filepath.Dir(p))
					t.Errorf("GetRealPath(%s) succeeded across escaping symlink, want error", filepath.Base(escapeLink))
				}
			}
		})
	}
}

func TestOpenOSFile(t *testing.T) {
	rootDir := t.TempDir()
	content := "disk-image-bytes"
	targetPath := filepath.Join(rootDir, "image.vmdk")
	if err := os.WriteFile(targetPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	realRoot := scalibrfs.RealFSScanRoot(rootDir)
	confinedRoot := scalibrfs.ConfinedScanRoot(rootDir)
	t.Cleanup(func() {
		if c, ok := confinedRoot.FS.(io.Closer); ok {
			_ = c.Close()
		}
	})

	for _, tc := range []struct {
		name string
		root *scalibrfs.ScanRoot
	}{
		{name: "real_fs", root: realRoot},
		{name: "confined_fs", root: confinedRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, cleanup, err := scalibrfs.OpenOSFile(tc.root, "image.vmdk", nil)
			if err != nil {
				t.Fatalf("OpenOSFile(%s): %v", tc.name, err)
			}
			// os.DirFS sets f.Name() to the full path, whereas os.Root sets f.Name() to the root-relative name.
			if gotBase := filepath.Base(f.Name()); gotBase != "image.vmdk" {
				t.Errorf("OpenOSFile(%s) copied to %q, want direct open of image.vmdk", tc.name, f.Name())
			}
			got, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("ReadAll(%s): %v", tc.name, err)
			}
			if string(got) != content {
				t.Errorf("OpenOSFile(%s) content = %q, want %q", tc.name, got, content)
			}
			// Closing the file before cleanup (e.g. via saferwall/pe) must not fail cleanup.
			if err := f.Close(); err != nil {
				t.Fatalf("f.Close(): %v", err)
			}
			if err := cleanup(); err != nil {
				t.Errorf("cleanup(%s): %v", tc.name, err)
			}
		})
	}

	if runtime.GOOS != "windows" {
		outside := filepath.Join(t.TempDir(), "outside.vmdk")
		if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(rootDir, "escape.vmdk")); err != nil {
			t.Fatal(err)
		}
		if f, c, err := scalibrfs.OpenOSFile(confinedRoot, "escape.vmdk", bytes.NewReader([]byte("dummy"))); err == nil {
			_ = f.Close()
			_ = c()
			t.Errorf("OpenOSFile(confined, escape.vmdk) succeeded across escaping symlink, want error")
		}
	}

	vf, vcleanup, err := scalibrfs.OpenOSFile(nil, "virtual.vmdk", bytes.NewReader([]byte(content)))
	if err != nil {
		t.Fatalf("OpenOSFile(virtual): %v", err)
	}
	tmpDir := filepath.Dir(vf.Name())
	vgot, err := io.ReadAll(vf)
	if err != nil {
		t.Fatalf("ReadAll(virtual): %v", err)
	}
	if string(vgot) != content {
		t.Errorf("OpenOSFile(virtual) content = %q, want %q", vgot, content)
	}
	if err := vf.Close(); err != nil {
		t.Fatalf("vf.Close(): %v", err)
	}
	if err := vcleanup(); err != nil {
		t.Errorf("cleanup(virtual): %v", err)
	}
	if _, err := os.Stat(tmpDir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("temp dir %q still exists after cleanup: %v", tmpDir, err)
	}
}

func TestOpenOSPath(t *testing.T) {
	rootDir := t.TempDir()
	content := "sqlite-db-bytes"
	if err := os.WriteFile(filepath.Join(rootDir, "local.sqlite"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "local.sqlite-wal"), []byte("sibling"), 0o644); err != nil {
		t.Fatal(err)
	}

	// RealFSScanRoot (unconfined DirFS) returns the in-place path without copying or deleting rootDir on cleanup.
	unconfinedRoot := scalibrfs.RealFSScanRoot(rootDir)
	inPlacePath, cleanup, err := scalibrfs.OpenOSPath(unconfinedRoot, "local.sqlite", nil)
	if err != nil {
		t.Fatalf("OpenOSPath(RealFSScanRoot): %v", err)
	}
	if inPlacePath != filepath.Join(rootDir, "local.sqlite") {
		t.Errorf("OpenOSPath(RealFSScanRoot) = %q, want %q", inPlacePath, filepath.Join(rootDir, "local.sqlite"))
	}
	if err := cleanup(); err != nil {
		t.Errorf("cleanup(RealFSScanRoot): %v", err)
	}
	if _, err := os.Stat(inPlacePath); err != nil {
		t.Fatalf("unconfined file %q removed by cleanup: %v", inPlacePath, err)
	}
	if _, _, err := scalibrfs.OpenOSPath(unconfinedRoot, "../outside", bytes.NewReader([]byte("x"))); err == nil {
		t.Errorf("OpenOSPath(RealFSScanRoot ../outside) succeeded, want error")
	}

	confinedRoot := scalibrfs.ConfinedScanRoot(rootDir)
	t.Cleanup(func() {
		if c, ok := confinedRoot.FS.(io.Closer); ok {
			_ = c.Close()
		}
	})

	// Mismatched ScanRoot.FS vs ScanRoot.Path must not return the mismatched host path in place.
	otherDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(otherDir, "local.sqlite"), []byte("wrong-root"), 0o644); err != nil {
		t.Fatal(err)
	}
	mismatchedRoot := &scalibrfs.ScanRoot{FS: scalibrfs.DirFS(rootDir), Path: otherDir}
	mismatchedPath, mismatchedCleanup, err := scalibrfs.OpenOSPath(mismatchedRoot, "local.sqlite", nil)
	if err != nil {
		t.Fatalf("OpenOSPath(mismatched): %v", err)
	}
	if filepath.Dir(mismatchedPath) == rootDir || filepath.Dir(mismatchedPath) == otherDir {
		t.Errorf("OpenOSPath(mismatched) returned in-place path %q, want isolated temp dir", mismatchedPath)
	}
	gotMismatched, err := os.ReadFile(mismatchedPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", mismatchedPath, err)
	}
	if string(gotMismatched) != content {
		t.Errorf("OpenOSPath(mismatched) content = %q, want %q", gotMismatched, content)
	}
	if err := mismatchedCleanup(); err != nil {
		t.Errorf("cleanup(mismatched): %v", err)
	}

	// ConfinedScanRoot and nil-FS ScanRoot copy to an isolated temp dir (without sibling -wal) and clean up.
	for _, tc := range []struct {
		name string
		root *scalibrfs.ScanRoot
	}{
		{name: "confined_scan_root", root: confinedRoot},
		{name: "nil_scan_root_fs", root: &scalibrfs.ScanRoot{Path: rootDir}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatedPath, isolatedCleanup, err := scalibrfs.OpenOSPath(tc.root, "local.sqlite", nil)
			if err != nil {
				t.Fatalf("OpenOSPath(%s): %v", tc.name, err)
			}
			if filepath.Dir(isolatedPath) == rootDir {
				t.Errorf("OpenOSPath(%s) returned in-place path %q, want isolated temp dir", tc.name, isolatedPath)
			}
			if _, err := os.Stat(isolatedPath + "-wal"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("sibling -wal exists next to isolated path %q: %v", isolatedPath, err)
			}
			got, err := os.ReadFile(isolatedPath)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", isolatedPath, err)
			}
			if string(got) != content {
				t.Errorf("OpenOSPath(%s) content = %q, want %q", tc.name, got, content)
			}
			isolatedDir := filepath.Dir(isolatedPath)
			if err := isolatedCleanup(); err != nil {
				t.Errorf("cleanup(%s): %v", tc.name, err)
			}
			if _, err := os.Stat(isolatedDir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("isolated temp dir %q still exists after cleanup: %v", isolatedDir, err)
			}
			if runtime.GOOS != "windows" {
				outside := filepath.Join(t.TempDir(), "outside.sqlite")
				if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
					t.Fatal(err)
				}
				escapeName := "escape-" + tc.name + ".sqlite"
				if err := os.Symlink(outside, filepath.Join(rootDir, escapeName)); err != nil {
					t.Fatal(err)
				}
				if p, c, err := scalibrfs.OpenOSPath(tc.root, escapeName, bytes.NewReader([]byte("dummy"))); err == nil {
					_ = c()
					t.Errorf("OpenOSPath(%s, %s) = %q across escaping symlink, want error", tc.name, escapeName, p)
				}
			}
		})
	}

	// Directories are rejected up front on both unconfined and confined roots.
	if err := os.Mkdir(filepath.Join(rootDir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scalibrfs.OpenOSPath(unconfinedRoot, "subdir", nil); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("OpenOSPath(unconfined dir) err = %v, want fs.ErrInvalid", err)
	}
	if _, err := scalibrfs.GetRealPath(confinedRoot, "subdir", nil); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("GetRealPath(confined dir) err = %v, want fs.ErrInvalid", err)
	}

	// Virtual reader copies to a temp dir and cleans up.
	vPath, vCleanup, err := scalibrfs.OpenOSPath(nil, "virtual.sqlite", bytes.NewReader([]byte(content)))
	if err != nil {
		t.Fatalf("OpenOSPath(virtual): %v", err)
	}
	vDir := filepath.Dir(vPath)
	if err := vCleanup(); err != nil {
		t.Errorf("cleanup(virtual): %v", err)
	}
	if _, err := os.Stat(vDir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("virtual temp dir %q still exists after cleanup: %v", vDir, err)
	}
}

func TestGetRealPath_SanitizesUnsafeBasename(t *testing.T) {
	tests := []struct {
		name     string
		relPath  string
		wantBase string
	}{
		{name: "safe_sqlite", relPath: "var/lib/rpm/rpmdb.sqlite", wantBase: "rpmdb.sqlite"},
		{name: "query_param", relPath: "dir/db.sql?mode=rw", wantBase: "file"},
		{name: "windows_reserved_colon", relPath: "dir/COM1:stream", wantBase: "file"},
		{name: "trailing_dot", relPath: "dir/bad.", wantBase: "file"},
		{name: "too_long", relPath: "dir/" + strings.Repeat("a", 129), wantBase: "file"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			realPath, err := scalibrfs.GetRealPath(nil, tc.relPath, bytes.NewReader([]byte("x")))
			if err != nil {
				t.Fatalf("GetRealPath(%q): %v", tc.relPath, err)
			}
			defer func() { _ = os.RemoveAll(filepath.Dir(realPath)) }()
			if got := filepath.Base(realPath); got != tc.wantBase {
				t.Errorf("GetRealPath(%q) base = %q, want %q", tc.relPath, got, tc.wantBase)
			}
		})
	}
}

func TestSQLiteReadOnlyURI(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{
			path: "/tmp/containers/storage/db.sql",
			want: "file:/tmp/containers/storage/db.sql?mode=ro&immutable=1",
		},
		{
			path: "/tmp/dir?k=v#frag/100%/db.sql",
			want: "file:/tmp/dir%3Fk=v%23frag/100%25/db.sql?mode=ro&immutable=1",
		},
		{
			path: "//server/share/db.sqlite",
			want: "file:////server/share/db.sqlite?mode=ro&immutable=1",
		},
		{
			path: "C:/ProgramData/winget/installed.db",
			want: "file:/C:/ProgramData/winget/installed.db?mode=ro&immutable=1",
		},
		{
			path: "testdata/db.sql",
			want: "file:testdata/db.sql?mode=ro&immutable=1",
		},
	}
	for _, tc := range tests {
		if got := scalibrfs.SQLiteReadOnlyURI(tc.path); got != tc.want {
			t.Errorf("SQLiteReadOnlyURI(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
