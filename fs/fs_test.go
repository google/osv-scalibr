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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

func TestDirFS_LazyAndClose(t *testing.T) {
	// DirFS("") returns a non-ErrNotExist error matching os.DirFS("").
	emptyFS := scalibrfs.DirFS("")
	if _, err := emptyFS.Stat("any"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("DirFS(\"\").Stat(any) = %v, want non-ErrNotExist error", err)
	}

	// DirFS must not open the directory eagerly so callers can construct
	// ScanRoot configs with placeholder paths before running a scan.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	lazyFS := scalibrfs.DirFS(missing)
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

	fsys := scalibrfs.DirFS(dir)
	b, err := fs.ReadFile(fsys, "hello.txt")
	if err != nil {
		t.Fatalf("ReadFile(hello.txt): %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("ReadFile(hello.txt) = %q, want %q", b, "hello")
	}

	closer, ok := fsys.(io.Closer)
	if !ok {
		t.Fatal("DirFS does not implement io.Closer")
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

func TestDirFS_Symlinks(t *testing.T) {
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

	fsys := scalibrfs.DirFS(root)
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

	scanRoot := scalibrfs.RealFSScanRoot(rootDir)
	t.Cleanup(func() {
		if c, ok := scanRoot.FS.(io.Closer); ok {
			_ = c.Close()
		}
	})

	for _, tc := range []struct {
		name string
		root *scalibrfs.ScanRoot
	}{
		{name: "with_scan_root_fs", root: scanRoot},
		{name: "with_nil_scan_root_fs", root: &scalibrfs.ScanRoot{Path: rootDir}},
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
			if runtime.GOOS != "windows" {
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

	scanRoot := scalibrfs.RealFSScanRoot(rootDir)
	t.Cleanup(func() {
		if c, ok := scanRoot.FS.(io.Closer); ok {
			_ = c.Close()
		}
	})

	f, cleanup, err := scalibrfs.OpenOSFile(scanRoot, "image.vmdk", nil)
	if err != nil {
		t.Fatalf("OpenOSFile(real fs): %v", err)
	}
	if filepath.Dir(f.Name()) != rootDir {
		t.Errorf("OpenOSFile(real fs) copied to %q, want direct open inside %q", f.Name(), rootDir)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll(real fs): %v", err)
	}
	if string(got) != content {
		t.Errorf("OpenOSFile(real fs) content = %q, want %q", got, content)
	}
	// Closing the file before cleanup (e.g. via saferwall/pe) must not fail cleanup.
	if err := f.Close(); err != nil {
		t.Fatalf("f.Close(): %v", err)
	}
	if err := cleanup(); err != nil {
		t.Errorf("cleanup(real fs): %v", err)
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

type subFSOpener interface {
	OpenSubFS(name string) (scalibrfs.FS, error)
}

type dirOpener interface {
	OpenDir(name string) (fs.ReadDirFile, error)
}

func TestDirFS_OpenSubFS(t *testing.T) {
	parent := t.TempDir()
	outsideDir := filepath.Join(parent, "outside")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("host-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(parent, "rootfs")
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "b", "leaf.txt"), []byte("leaf-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("top-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	fsys := scalibrfs.DirFS(root)
	t.Cleanup(func() {
		if c, ok := fsys.(io.Closer); ok {
			_ = c.Close()
		}
	})

	opener, ok := fsys.(subFSOpener)
	if !ok {
		t.Fatal("DirFS does not implement OpenSubFS")
	}

	subA, err := opener.OpenSubFS("a")
	if err != nil {
		t.Fatalf("OpenSubFS(a): %v", err)
	}
	subOpenerA, ok := subA.(subFSOpener)
	if !ok {
		t.Fatal("child FS does not implement OpenSubFS")
	}
	subB, err := subOpenerA.OpenSubFS("b")
	if err != nil {
		t.Fatalf("subA.OpenSubFS(b): %v", err)
	}

	got, err := fs.ReadFile(subB, "leaf.txt")
	if err != nil {
		t.Fatalf("subB.ReadFile(leaf.txt): %v", err)
	}
	if string(got) != "leaf-data" {
		t.Errorf("subB.ReadFile(leaf.txt) = %q, want %q", got, "leaf-data")
	}
	if _, err := subB.Stat("leaf.txt"); err != nil {
		t.Errorf("subB.Stat(leaf.txt): %v", err)
	}
	entries, err := subB.ReadDir(".")
	if err != nil || len(entries) != 1 || entries[0].Name() != "leaf.txt" {
		t.Errorf("subB.ReadDir(.) = (%v, %v), want [leaf.txt]", entries, err)
	}

	// Closing a child sub-FS must return fs.ErrClosed on further use and not affect the parent.
	closerB, ok := subB.(io.Closer)
	if !ok {
		t.Fatal("child FS does not implement io.Closer")
	}
	if err := closerB.Close(); err != nil {
		t.Fatalf("subB.Close(): %v", err)
	}
	if _, err := subB.Open("leaf.txt"); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("subB.Open after Close = %v, want fs.ErrClosed", err)
	}
	if _, err := subB.Stat("leaf.txt"); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("subB.Stat after Close = %v, want fs.ErrClosed", err)
	}
	if _, err := subB.ReadDir("."); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("subB.ReadDir after Close = %v, want fs.ErrClosed", err)
	}
	if closerA, ok := subA.(io.Closer); ok {
		if err := closerA.Close(); err != nil {
			t.Fatalf("subA.Close(): %v", err)
		}
	}
	if _, err := fsys.Stat("a/b/leaf.txt"); err != nil {
		t.Errorf("parent Stat(a/b/leaf.txt) after child Close: %v", err)
	}

	// Invalid paths and regular files must be rejected.
	invalidPaths := []string{"..", "/a", "../outside"}
	if runtime.GOOS == "windows" {
		invalidPaths = append(invalidPaths, `a\b`, "C:a")
	}
	for _, p := range invalidPaths {
		if sub, err := opener.OpenSubFS(p); err == nil {
			if c, ok := sub.(io.Closer); ok {
				_ = c.Close()
			}
			t.Errorf("OpenSubFS(%q) succeeded, want error", p)
		} else if !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("OpenSubFS(%q) err = %v, want fs.ErrInvalid", p, err)
		}
	}
	if sub, err := opener.OpenSubFS("top.txt"); err == nil {
		if c, ok := sub.(io.Closer); ok {
			_ = c.Close()
		}
		t.Error("OpenSubFS(top.txt) on regular file succeeded, want error")
	}

	// Closed subRoot under os.Getwd() must still return fs.ErrClosed (never trigger runfiles fallback).
	wdFS := scalibrfs.DirFS(".")
	t.Cleanup(func() {
		if c, ok := wdFS.(io.Closer); ok {
			_ = c.Close()
		}
	})
	if wdOpener, ok := wdFS.(subFSOpener); ok {
		wdSub, err := wdOpener.OpenSubFS(".")
		if err != nil {
			t.Fatalf("wdFS.OpenSubFS(.): %v", err)
		}
		if err := wdSub.(io.Closer).Close(); err != nil {
			t.Fatalf("wdSub.Close(): %v", err)
		}
		if _, err := wdSub.Open("."); !errors.Is(err, fs.ErrClosed) {
			t.Errorf("closed wdSub.Open(.) = %v, want fs.ErrClosed", err)
		}
		if sub, err := wdSub.(subFSOpener).OpenSubFS("."); err == nil {
			if c, ok := sub.(io.Closer); ok {
				_ = c.Close()
			}
			t.Error("closed wdSub.OpenSubFS(.) succeeded, want fs.ErrClosed")
		} else if !errors.Is(err, fs.ErrClosed) {
			t.Errorf("closed wdSub.OpenSubFS(.) = %v, want fs.ErrClosed", err)
		}
		if d, err := wdSub.(dirOpener).OpenDir("."); err == nil {
			_ = d.Close()
			t.Error("closed wdSub.OpenDir(.) succeeded, want fs.ErrClosed")
		} else if !errors.Is(err, fs.ErrClosed) {
			t.Errorf("closed wdSub.OpenDir(.) = %v, want fs.ErrClosed", err)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}

	// Symlink confinement on OpenSubFS.
	if err := os.Symlink(outsideDir, filepath.Join(root, "escape-abs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(root, "escape-rel")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/a/b", filepath.Join(root, "intra-abs-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../top.txt", filepath.Join(root, "a", "up-to-parent")); err != nil {
		t.Fatal(err)
	}
	// Intra-root absolute symlink inside child dir "a" whose target "/b/leaf.txt"
	// matches a decoy "a/b/leaf.txt" under the child root, plus a symlink "/b" to
	// decoy directory "a/b" and a scan-root-valid symlink "/a/b/leaf.txt".
	if err := os.Symlink("/b/leaf.txt", filepath.Join(root, "a", "abs-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/b", filepath.Join(root, "a", "abs-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/a/b/leaf.txt", filepath.Join(root, "a", "root-abs-link")); err != nil {
		t.Fatal(err)
	}

	for _, esc := range []string{"escape-abs", "escape-rel"} {
		if sub, err := opener.OpenSubFS(esc); err == nil {
			if c, ok := sub.(io.Closer); ok {
				_ = c.Close()
			}
			t.Errorf("OpenSubFS(%q) succeeded across escaping symlink, want error", esc)
		}
	}

	intraSub, err := opener.OpenSubFS("intra-abs-dir")
	if err != nil {
		t.Fatalf("OpenSubFS(intra-abs-dir): %v", err)
	}
	if c, ok := intraSub.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}
	if got, err := fs.ReadFile(intraSub, "leaf.txt"); err != nil || string(got) != "leaf-data" {
		t.Errorf("intraSub.ReadFile(leaf.txt) = (%q, %v), want (%q, nil)", got, err, "leaf-data")
	}

	// Child sub-FS rooted at "a" must confine symlinks targeting parent "../top.txt"
	// and must not rewrite absolute symlinks against the subdirectory root.
	confinedA, err := opener.OpenSubFS("a")
	if err != nil {
		t.Fatalf("OpenSubFS(a): %v", err)
	}
	if c, ok := confinedA.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}
	if f, err := confinedA.Open("up-to-parent"); err == nil {
		_ = f.Close()
		t.Error("confinedA.Open(up-to-parent) escaped child root, want error")
	}
	if f, err := confinedA.Open("abs-link"); err == nil {
		_ = f.Close()
		t.Error("confinedA.Open(abs-link) resolved absolute symlink against child root decoy, want error")
	}
	if _, err := confinedA.Stat("abs-link"); err == nil {
		t.Error("confinedA.Stat(abs-link) resolved absolute symlink against child root decoy, want error")
	}
	if sub, err := confinedA.(subFSOpener).OpenSubFS("abs-dir"); err == nil {
		if c, ok := sub.(io.Closer); ok {
			_ = c.Close()
		}
		t.Error("confinedA.OpenSubFS(abs-dir) resolved absolute symlink against child root decoy, want error")
	}
	if d, err := confinedA.(dirOpener).OpenDir("abs-dir"); err == nil {
		_ = d.Close()
		t.Error("confinedA.OpenDir(abs-dir) resolved absolute symlink against child root decoy, want error")
	}
	// Top-level scan root still resolves /a/b/leaf.txt, while child sub-FS rejects it.
	if got, err := fs.ReadFile(fsys, "a/root-abs-link"); err != nil || string(got) != "leaf-data" {
		t.Errorf("fsys.ReadFile(a/root-abs-link) = (%q, %v), want (%q, nil)", got, err, "leaf-data")
	}
	if f, err := confinedA.Open("root-abs-link"); err == nil {
		_ = f.Close()
		t.Error("confinedA.Open(root-abs-link) succeeded on child subRoot, want error")
	}
}

func TestDirFS_OpenDirAndReadDir(t *testing.T) {
	parent := t.TempDir()
	outsideFile := filepath.Join(parent, "host-secret.txt")
	if err := os.WriteFile(outsideFile, []byte("top-secret-data"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(parent, "rootfs")
	manyDir := filepath.Join(root, "many")
	if err := os.MkdirAll(filepath.Join(manyDir, "subdir-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "regular.txt"), []byte("reg"), 0o644); err != nil {
		t.Fatal(err)
	}

	const numFiles = 150
	wantNames := make([]string, 0, numFiles+2)
	wantNames = append(wantNames, "subdir-a")
	for i := range numFiles {
		name := fmt.Sprintf("f-%03d.txt", i)
		wantNames = append(wantNames, name)
		content := fmt.Sprintf("payload-%03d", i)
		if err := os.WriteFile(filepath.Join(manyDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(outsideFile, filepath.Join(manyDir, "escape-link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/many", filepath.Join(root, "many-abs-link")); err != nil {
			t.Fatal(err)
		}
		wantNames = append(wantNames, "escape-link")
	}
	slices.Sort(wantNames)

	fsys := scalibrfs.DirFS(root)
	t.Cleanup(func() {
		if c, ok := fsys.(io.Closer); ok {
			_ = c.Close()
		}
	})

	// Sorted ReadDir verifies entry names, types, and confined Info() behavior.
	entries, err := fsys.ReadDir("many")
	if err != nil {
		t.Fatalf("ReadDir(many): %v", err)
	}
	gotNames := make([]string, 0, len(entries))
	for _, e := range entries {
		gotNames = append(gotNames, e.Name())
		switch e.Name() {
		case "subdir-a":
			if !e.IsDir() || e.Type()&fs.ModeDir == 0 {
				t.Errorf("subdir-a IsDir=%v Type=%v, want dir", e.IsDir(), e.Type())
			}
			info, err := e.Info()
			if err != nil || !info.IsDir() {
				t.Errorf("subdir-a Info() = (%v, %v), want dir info", info, err)
			}
		case "escape-link":
			if e.IsDir() || e.Type()&fs.ModeSymlink == 0 {
				t.Errorf("escape-link IsDir=%v Type=%v, want symlink", e.IsDir(), e.Type())
			}
			// Info() must use confined Lstat (reporting symlink mode), never following the escape target.
			info, err := e.Info()
			if err != nil {
				t.Errorf("escape-link Info(): %v", err)
			} else if info.Mode()&fs.ModeSymlink == 0 {
				t.Errorf("escape-link Info().Mode() = %v, want ModeSymlink", info.Mode())
			}
		default:
			if e.IsDir() || !e.Type().IsRegular() {
				t.Errorf("%s IsDir=%v Type=%v, want regular file", e.Name(), e.IsDir(), e.Type())
			}
			if e.Name() == "f-000.txt" {
				info, err := e.Info()
				if err != nil {
					t.Errorf("f-000.txt Info(): %v", err)
				} else if wantSize := int64(len("payload-000")); info.Size() != wantSize {
					t.Errorf("f-000.txt Size() = %d, want %d", info.Size(), wantSize)
				}
			}
		}
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Errorf("ReadDir(many) returned %d entries, want %d sorted entries", len(gotNames), len(wantNames))
	}

	// Streaming OpenDir across multiple batches.
	opener, ok := fsys.(dirOpener)
	if !ok {
		t.Fatal("DirFS does not implement OpenDir")
	}
	dirFile, err := opener.OpenDir("many")
	if err != nil {
		t.Fatalf("OpenDir(many): %v", err)
	}
	var streamedNames []string
	for {
		batch, err := dirFile.ReadDir(30)
		for _, e := range batch {
			streamedNames = append(streamedNames, e.Name())
			if e.Name() == "f-042.txt" {
				info, infoErr := e.Info()
				if infoErr != nil || info.Size() != int64(len("payload-042")) {
					t.Errorf("streamed f-042.txt Info() = (%v, %v), want size %d", info, infoErr, len("payload-042"))
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("dirFile.ReadDir(30): %v", err)
		}
	}
	if err := dirFile.Close(); err != nil {
		t.Errorf("dirFile.Close(): %v", err)
	}
	slices.Sort(streamedNames)
	if !slices.Equal(streamedNames, wantNames) {
		t.Errorf("OpenDir(many) streamed %d entries, want %d", len(streamedNames), len(wantNames))
	}

	// Empty directory, missing directory, regular file, and invalid path.
	emptyEntries, err := fsys.ReadDir("empty")
	if err != nil || len(emptyEntries) != 0 {
		t.Errorf("ReadDir(empty) = (%v, %v), want empty", emptyEntries, err)
	}
	if _, err := fsys.ReadDir("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadDir(missing) err = %v, want fs.ErrNotExist", err)
	}
	if _, err := fsys.ReadDir("regular.txt"); err == nil {
		t.Error("ReadDir(regular.txt) succeeded, want error")
	}
	if _, err := fsys.ReadDir(".."); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("ReadDir(..) err = %v, want fs.ErrInvalid", err)
	}
	if d, err := opener.OpenDir(".."); err == nil {
		_ = d.Close()
		t.Error("OpenDir(..) succeeded, want fs.ErrInvalid")
	} else if !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("OpenDir(..) err = %v, want fs.ErrInvalid", err)
	}

	if runtime.GOOS != "windows" {
		linkDir, err := opener.OpenDir("many-abs-link")
		if err != nil {
			t.Fatalf("OpenDir(many-abs-link): %v", err)
		}
		defer func() { _ = linkDir.Close() }()
		linkEntries, err := linkDir.ReadDir(-1)
		if err != nil {
			t.Fatalf("linkDir.ReadDir(-1): %v", err)
		}
		if len(linkEntries) != len(wantNames) {
			t.Errorf("OpenDir(many-abs-link) got %d entries, want %d", len(linkEntries), len(wantNames))
		}
		for _, e := range linkEntries {
			if e.Name() == "f-001.txt" {
				if info, err := e.Info(); err != nil || info.Size() != int64(len("payload-001")) {
					t.Errorf("many-abs-link f-001.txt Info() = (%v, %v), want size %d", info, err, len("payload-001"))
				}
			}
		}
	}
}

func BenchmarkDirFS_ReadDir(b *testing.B) {
	root := b.TempDir()
	sub := filepath.Join(root, "a", "b", "c", "d", "e")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		b.Fatal(err)
	}
	for i := range 100 {
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f-%03d.txt", i)), []byte("x"), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	fsys := scalibrfs.DirFS(root)
	b.Cleanup(func() {
		if c, ok := fsys.(io.Closer); ok {
			_ = c.Close()
		}
	})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		entries, err := fsys.ReadDir("a/b/c/d/e")
		if err != nil {
			b.Fatal(err)
		}
		if len(entries) != 100 {
			b.Fatalf("ReadDir len = %d, want 100", len(entries))
		}
	}
}
