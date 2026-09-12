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

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirFSRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")

	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q): %v", root, err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q): %v", outside, err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0644); err != nil {
		t.Fatalf("os.WriteFile(outside): %v", err)
	}
	if err := os.Symlink("../outside", filepath.Join(root, "link")); err != nil {
		t.Skipf("os.Symlink(): %v", err)
	}

	fsys := DirFS(root)

	f, err := fsys.Open("link/secret.txt")
	if err == nil {
		_ = f.Close()
		t.Fatalf("DirFS(%q).Open(%q) succeeded through a symlink outside the root", root, "link/secret.txt")
	}
}

func TestDirFSAllowsInRootSymlink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	target := filepath.Join(root, "target")

	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q): %v", target, err)
	}
	if err := os.WriteFile(filepath.Join(target, "file.txt"), []byte("inside"), 0644); err != nil {
		t.Fatalf("os.WriteFile(target): %v", err)
	}
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Skipf("os.Symlink(): %v", err)
	}

	fsys := DirFS(root)

	f, err := fsys.Open("link/file.txt")
	if err != nil {
		t.Fatalf("DirFS(%q).Open(%q): %v", root, "link/file.txt", err)
	}
	defer f.Close()
}
