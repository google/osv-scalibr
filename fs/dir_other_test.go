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

//go:build !unix

package fs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenDir_NonUnix(t *testing.T) {
	root := t.TempDir()
	subDir := filepath.Join(root, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := DirFS(root).(*rootFS)
	t.Cleanup(func() { _ = r.Close() })

	dirFile, err := r.OpenDir("sub")
	if err != nil {
		t.Fatalf("OpenDir(sub): %v", err)
	}
	entries, err := dirFile.ReadDir(-1)
	if closeErr := dirFile.Close(); closeErr != nil {
		t.Errorf("Close(sub): %v", closeErr)
	}
	if err != nil {
		t.Fatalf("ReadDir(sub): %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "hello.txt" {
		t.Errorf("OpenDir(sub) entries = %v, want [hello.txt]", entries)
	}

	if d, err := r.OpenDir("missing"); err == nil {
		_ = d.Close()
		t.Error("OpenDir(missing) succeeded, want fs.ErrNotExist")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenDir(missing) err = %v, want fs.ErrNotExist", err)
	}

	if d, err := r.OpenDir(".."); err == nil {
		_ = d.Close()
		t.Error("OpenDir(..) succeeded, want fs.ErrInvalid")
	} else if !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("OpenDir(..) err = %v, want fs.ErrInvalid", err)
	}
}
