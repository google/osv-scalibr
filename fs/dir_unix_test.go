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

package fs_test

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestOpenDir_UnixConfinedFastPathAndFIFO(t *testing.T) {
	root := t.TempDir()
	subDir := filepath.Join(root, "sub")
	if err := os.MkdirAll(filepath.Join(subDir, "decoy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "vanish.txt"), []byte("bye"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "regular.txt"), []byte("reg"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.fifo"), 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	if err := os.Symlink("sub", filepath.Join(root, "rel-sub-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/sub", filepath.Join(root, "sub-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/decoy", filepath.Join(subDir, "abs-decoy")); err != nil {
		t.Fatal(err)
	}

	fsys := scalibrfs.DirFS(root)
	t.Cleanup(func() {
		if c, ok := fsys.(io.Closer); ok {
			_ = c.Close()
		}
	})
	opener := fsys.(dirOpener)
	subOpener := fsys.(subFSOpener)

	// OpenDir on Unix Go 1.26+ must return the wrapped confinedReadDirFile
	// (not raw *os.File) so d_type fast paths stay active while Info() remains
	// root.Lstat-confined.
	for _, dirPath := range []string{"sub", "rel-sub-link", "sub-link"} {
		dirFile, err := opener.OpenDir(dirPath)
		if err != nil {
			t.Fatalf("OpenDir(%q): %v", dirPath, err)
		}
		if _, isOSFile := dirFile.(*os.File); isOSFile {
			_ = dirFile.Close()
			t.Fatalf("OpenDir(%q) returned raw *os.File, want wrapped confined ReadDirFile", dirPath)
		}
		entries, err := dirFile.ReadDir(-1)
		if err != nil {
			_ = dirFile.Close()
			t.Fatalf("ReadDir(%q): %v", dirPath, err)
		}
		if err := dirFile.Close(); err != nil {
			t.Errorf("Close(%q): %v", dirPath, err)
		}
		var sawHello bool
		for _, e := range entries {
			if got, want := fmt.Sprint(e), fs.FormatDirEntry(e); got != want {
				t.Errorf("String() for %q = %q, want %q", e.Name(), got, want)
			}
			if e.Name() == "hello.txt" {
				sawHello = true
				info, err := e.Info()
				if err != nil || info.Size() != 5 {
					t.Errorf("hello.txt Info() = (%v, %v), want size 5", info, err)
				}
			}
		}
		if !sawHello {
			t.Errorf("OpenDir(%q) missing hello.txt", dirPath)
		}
	}

	// Vanished file through intra-root absolute directory symlink must report
	// the caller's symlinked directory prefix in PathError.Path.
	linkDir, err := opener.OpenDir("sub-link")
	if err != nil {
		t.Fatalf("OpenDir(sub-link): %v", err)
	}
	linkEntries, err := linkDir.ReadDir(-1)
	_ = linkDir.Close()
	if err != nil {
		t.Fatalf("linkDir.ReadDir(-1): %v", err)
	}
	if err := os.Remove(filepath.Join(subDir, "vanish.txt")); err != nil {
		t.Fatal(err)
	}
	for _, e := range linkEntries {
		if e.Name() != "vanish.txt" {
			continue
		}
		_, infoErr := e.Info()
		var pathErr *fs.PathError
		if !errors.As(infoErr, &pathErr) || pathErr.Path != "sub-link/vanish.txt" {
			t.Errorf("vanish.txt Info() err = %v, want *fs.PathError with Path %q", infoErr, "sub-link/vanish.txt")
		}
	}

	// OpenDir and OpenSubFS on a FIFO must fail immediately without blocking.
	if f, err := opener.OpenDir("pipe.fifo"); err == nil {
		_ = f.Close()
		t.Error("OpenDir(pipe.fifo) succeeded, want error")
	}
	if sub, err := subOpener.OpenSubFS("pipe.fifo"); err == nil {
		if c, ok := sub.(io.Closer); ok {
			_ = c.Close()
		}
		t.Error("OpenSubFS(pipe.fifo) succeeded, want error")
	}

	// Child sub-FS must not rewrite intra-root absolute symlinks against the subdirectory.
	subFS, err := subOpener.OpenSubFS("sub")
	if err != nil {
		t.Fatalf("OpenSubFS(sub): %v", err)
	}
	t.Cleanup(func() {
		if c, ok := subFS.(io.Closer); ok {
			_ = c.Close()
		}
	})
	if f, err := subFS.(dirOpener).OpenDir("abs-decoy"); err == nil {
		_ = f.Close()
		t.Error("subFS.OpenDir(abs-decoy) resolved absolute symlink against subdir decoy, want error")
	}
}
