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
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

func populateShallowTree(tb testing.TB, dir string, numDirs, filesPerDir int) {
	tb.Helper()
	payload := []byte("package-metadata-data")
	for d := range numDirs {
		sub := filepath.Join(dir, fmt.Sprintf("dir%d", d))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			tb.Fatal(err)
		}
		for f := range filesPerDir {
			if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("file%d.txt", f)), payload, 0o644); err != nil {
				tb.Fatal(err)
			}
		}
	}
}

func populateDeepTree(tb testing.TB, dir string) {
	tb.Helper()
	payload := []byte("package-metadata-data")
	// 5 * 5 * 5 = 125 leaf directories at depth 4 (files at depth 5: aX/bY/cZ/leaf/fileW.txt),
	// 20 files per leaf dir = 2,500 files total across 281 directories.
	for a := range 5 {
		for b := range 5 {
			for c := range 5 {
				leaf := filepath.Join(
					dir,
					fmt.Sprintf("a%d", a),
					fmt.Sprintf("b%d", b),
					fmt.Sprintf("c%d", c),
					"leaf",
				)
				if err := os.MkdirAll(leaf, 0o755); err != nil {
					tb.Fatal(err)
				}
				for f := range 20 {
					if err := os.WriteFile(filepath.Join(leaf, fmt.Sprintf("file%d.txt", f)), payload, 0o644); err != nil {
						tb.Fatal(err)
					}
				}
			}
		}
	}
}

func runWalkDirOpenTraversal(fsys scalibrfs.FS) (int, error) {
	ops := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			ops++
			return nil
		}
		ops++
		f, err := fsys.Open(p)
		if err != nil {
			return err
		}
		return f.Close()
	})
	ops++
	return ops, err
}

// runScalibrStyleTraversal mirrors SCALIBR's WalkDirUnsorted + diriterate.ReadDir
// (which executes fsys.Stat(dir) + fsys.Open(dir) + ReadDir(1) on every directory)
// plus Stat + Lstat + Open on every visited file.
func runScalibrStyleTraversal(fsys scalibrfs.FS) (int, error) {
	ops := 0
	var walk func(rel string) error
	walk = func(rel string) error {
		ops++
		if _, err := fsys.Stat(rel); err != nil {
			return err
		}
		ops++
		dirFile, err := fsys.Open(rel)
		if err != nil {
			return err
		}
		rdf, ok := dirFile.(fs.ReadDirFile)
		if !ok {
			_ = dirFile.Close()
			return fmt.Errorf("not a ReadDirFile: %T", dirFile)
		}
		var subDirs []string
		var files []string
		for {
			entries, err := rdf.ReadDir(1)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				_ = dirFile.Close()
				return err
			}
			for _, entry := range entries {
				child := entry.Name()
				if rel != "." {
					child = path.Join(rel, child)
				}
				if entry.IsDir() {
					subDirs = append(subDirs, child)
				} else {
					files = append(files, child)
				}
			}
		}
		_ = dirFile.Close()

		for _, file := range files {
			ops++
			if _, err := fs.Lstat(fsys, file); err != nil {
				return err
			}
			ops++
			if _, err := fsys.Stat(file); err != nil {
				return err
			}
			ops++
			f, err := fsys.Open(file)
			if err != nil {
				return err
			}
			_ = f.Close()
		}
		for _, sub := range subDirs {
			if err := walk(sub); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(".")
	return ops, err
}

func TestDirFSTraversal(t *testing.T) {
	shallowDir := t.TempDir()
	populateShallowTree(t, shallowDir, 25, 100)

	deepDir := t.TempDir()
	populateDeepTree(t, deepDir)

	workloads := []struct {
		name string
		dir  string
		run  func(scalibrfs.FS) (int, error)
	}{
		{
			name: "Shallow_Depth2_2500Files_WalkDirOpen",
			dir:  shallowDir,
			run:  runWalkDirOpenTraversal,
		},
		{
			name: "Shallow_Depth2_2500Files_ScalibrWalkStatLstatOpen",
			dir:  shallowDir,
			run:  runScalibrStyleTraversal,
		},
		{
			name: "Deep_Depth5_2500Files_WalkDirOpen",
			dir:  deepDir,
			run:  runWalkDirOpenTraversal,
		},
		{
			name: "Deep_Depth5_2500Files_ScalibrWalkStatLstatOpen",
			dir:  deepDir,
			run:  runScalibrStyleTraversal,
		},
	}

	for _, wl := range workloads {
		t.Run(wl.name, func(t *testing.T) {
			fsys := scalibrfs.DirFS(wl.dir)
			start := time.Now()
			ops, err := wl.run(fsys)
			elapsed := time.Since(start)
			if closer, ok := fsys.(io.Closer); ok {
				if closeErr := closer.Close(); closeErr != nil {
					t.Fatalf("Close(): %v", closeErr)
				}
			}
			if err != nil {
				t.Fatalf("traversal failed: %v", err)
			}
			perOp := elapsed / time.Duration(ops)
			t.Logf("[GOOS=%s] %s: %v (%d ops, %v/op)", runtime.GOOS, wl.name, elapsed, ops, perOp)
		})
	}
}

func BenchmarkDirFSTraversal(b *testing.B) {
	shallowDir := b.TempDir()
	populateShallowTree(b, shallowDir, 25, 100)

	deepDir := b.TempDir()
	populateDeepTree(b, deepDir)

	workloads := []struct {
		name string
		dir  string
		run  func(scalibrfs.FS) (int, error)
	}{
		{
			name: "Shallow_Depth2_2500Files_WalkDirOpen",
			dir:  shallowDir,
			run:  runWalkDirOpenTraversal,
		},
		{
			name: "Shallow_Depth2_2500Files_ScalibrWalkStatLstatOpen",
			dir:  shallowDir,
			run:  runScalibrStyleTraversal,
		},
		{
			name: "Deep_Depth5_2500Files_WalkDirOpen",
			dir:  deepDir,
			run:  runWalkDirOpenTraversal,
		},
		{
			name: "Deep_Depth5_2500Files_ScalibrWalkStatLstatOpen",
			dir:  deepDir,
			run:  runScalibrStyleTraversal,
		},
	}

	for _, wl := range workloads {
		b.Run(wl.name, func(b *testing.B) {
			for range b.N {
				fsys := scalibrfs.DirFS(wl.dir)
				if _, err := wl.run(fsys); err != nil {
					b.Fatalf("traversal: %v", err)
				}
				if closer, ok := fsys.(io.Closer); ok {
					_ = closer.Close()
				}
			}
		})
	}
}
