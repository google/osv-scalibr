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
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestSub(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "chroot", "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "chroot", "etc", "os-release"), []byte("ID=debian\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outer"), []byte("outer\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sub := scalibrfs.Sub(scalibrfs.DirFS(root), "chroot")

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
