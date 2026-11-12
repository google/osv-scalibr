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

package diriterate_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
)

func TestReadDir_ReadableDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "visible"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "visible", "file"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	it, err := diriterate.ReadDir(scalibrfs.DirFS(dir), "visible")
	if err != nil {
		t.Fatalf("ReadDir(visible) returned error: %v", err)
	}
	defer it.Close()

	var got []string
	for {
		e, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next() returned error: %v", err)
		}
		got = append(got, e.Name())
	}
	if len(got) != 1 || got[0] != "file" {
		t.Errorf("ReadDir(visible) entries = %v, want [file]", got)
	}
}

func TestReadDir_PermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions are not enforced via chmod on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}

	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	//nolint:errcheck
	defer os.Chmod(blocked, 0700) // avoid errors on cleanup

	_, err := diriterate.ReadDir(scalibrfs.DirFS(dir), "blocked")
	if err == nil {
		t.Fatal("ReadDir(blocked) returned no error, want permission error")
	}
	if !os.IsPermission(err) {
		t.Errorf("ReadDir(blocked) error = %v, want os.IsPermission to be true", err)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("ReadDir(blocked) error = %v, want errors.Is(err, fs.ErrPermission)", err)
	}
}
