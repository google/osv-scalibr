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

//go:build unix

package fs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenDir_ConfinedFastPathAndSafety(t *testing.T) {
	root := t.TempDir()
	subDir := filepath.Join(root, "sub")
	if err := os.MkdirAll(filepath.Join(subDir, "decoy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "regular.txt"), []byte("reg"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.fifo"), 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	if err := os.Symlink("/sub", filepath.Join(root, "sub-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/decoy", filepath.Join(subDir, "abs-decoy")); err != nil {
		t.Fatal(err)
	}

	r := DirFS(root).(*rootFS)
	t.Cleanup(func() { _ = r.Close() })

	// OpenDir must return *confinedReadDirFile and *confinedDirEntry so Unix d_type
	// fast paths stay active while DirEntry.Info() remains root.Lstat-confined.
	for _, dirPath := range []string{"sub", "sub-link"} {
		dirFile, err := r.OpenDir(dirPath)
		if err != nil {
			t.Fatalf("OpenDir(%q): %v", dirPath, err)
		}
		confined, ok := dirFile.(*confinedReadDirFile)
		if !ok {
			_ = dirFile.Close()
			t.Fatalf("OpenDir(%q) returned %T, want *confinedReadDirFile", dirPath, dirFile)
		}
		entries, err := confined.ReadDir(-1)
		if err != nil {
			_ = confined.Close()
			t.Fatalf("ReadDir(%q): %v", dirPath, err)
		}
		if err := confined.Close(); err != nil {
			t.Errorf("Close(%q): %v", dirPath, err)
		}
		var sawHello bool
		for _, e := range entries {
			ce, ok := e.(*confinedDirEntry)
			if !ok {
				t.Errorf("ReadDir(%q) entry %q has type %T, want *confinedDirEntry", dirPath, e.Name(), e)
				continue
			}
			if got, want := fmt.Sprint(ce), fs.FormatDirEntry(ce); got != want {
				t.Errorf("String() for %q = %q, want %q", ce.Name(), got, want)
			}
			if ce.Name() == "hello.txt" {
				sawHello = true
				info, err := ce.Info()
				if err != nil || info.Size() != 5 {
					t.Errorf("hello.txt Info() = (%v, %v), want size 5", info, err)
				}
			}
		}
		if !sawHello {
			t.Errorf("OpenDir(%q) missing hello.txt", dirPath)
		}
	}

	// OpenDir on a FIFO must fail immediately via O_DIRECTORY without blocking.
	if f, err := r.OpenDir("pipe.fifo"); err == nil {
		_ = f.Close()
		t.Error("OpenDir(pipe.fifo) succeeded, want error")
	}

	// OpenDir on a regular file must fail immediately via O_DIRECTORY.
	if f, err := r.OpenDir("regular.txt"); err == nil {
		_ = f.Close()
		t.Error("OpenDir(regular.txt) succeeded, want error")
	}

	// Child subRoot must not rewrite intra-root absolute symlinks against the subdirectory.
	subFS, err := r.OpenSubFS("sub")
	if err != nil {
		t.Fatalf("OpenSubFS(sub): %v", err)
	}
	subRoot := subFS.(*rootFS)
	t.Cleanup(func() { _ = subRoot.Close() })
	if f, err := subRoot.OpenDir("abs-decoy"); err == nil {
		_ = f.Close()
		t.Error("subRoot.OpenDir(abs-decoy) resolved absolute symlink against subdir decoy, want error")
	}
}
