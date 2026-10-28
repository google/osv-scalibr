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
	for _, missingPath := range []string{"etc/dangling-os-release", "lib64/missing.so"} {
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
				if p, err := scalibrfs.GetRealPath(tc.root, filepath.Base(escapeLink), nil); err == nil {
					_ = os.RemoveAll(filepath.Dir(p))
					t.Errorf("GetRealPath(%s) succeeded across escaping symlink, want error", filepath.Base(escapeLink))
				}
			}
		})
	}
}
