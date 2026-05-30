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

package image

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/artifact/image/require"
)

// TestFromTarball_FileRequirerFiltersRegularFiles verifies that a Config with a
// FileRequirer materializes only the regular files it requires, while keeping
// directories so the virtual filesystem stays navigable.
func TestFromTarball_FileRequirerFiltersRegularFiles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FileRequirer = require.NewFileRequirerPaths([]string{"dir1/bar.txt"})

	img, err := FromTarball(filepath.Join(testdataDir, "multiple-files.tar"), cfg)
	if err != nil {
		t.Fatalf("FromTarball returned error: %v", err)
	}
	defer func() { _ = img.CleanUp() }()
	fsys := img.FS()

	// The required regular file is materialized with its content.
	if got, err := fs.ReadFile(fsys, "dir1/bar.txt"); err != nil {
		t.Errorf("required file dir1/bar.txt missing: %v", err)
	} else if string(got) != "bar\n" {
		t.Errorf("dir1/bar.txt content = %q, want %q", got, "bar\n")
	}

	// Regular files no requirer wants are not materialized.
	for _, p := range []string{"foo.txt", "dir1/baz.txt"} {
		if _, err := fs.Stat(fsys, p); err == nil {
			t.Errorf("non-required file %q was materialized, want absent", p)
		}
	}

	// Directories are always kept so the tree remains navigable.
	if fi, err := fs.Stat(fsys, "dir1"); err != nil {
		t.Errorf("dir1 should remain present: %v", err)
	} else if !fi.IsDir() {
		t.Errorf("dir1 should be a directory")
	}
}

// TestFromTarball_NilFileRequirerKeepsAllFiles verifies the default (nil
// requirer / FileRequirerAll) is unchanged: every file is materialized.
func TestFromTarball_NilFileRequirerKeepsAllFiles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FileRequirer = nil // validateConfig defaults this to FileRequirerAll

	img, err := FromTarball(filepath.Join(testdataDir, "multiple-files.tar"), cfg)
	if err != nil {
		t.Fatalf("FromTarball returned error: %v", err)
	}
	defer func() { _ = img.CleanUp() }()
	fsys := img.FS()

	for _, p := range []string{"foo.txt", "dir1/bar.txt", "dir1/baz.txt"} {
		if _, err := fs.Stat(fsys, p); err != nil {
			t.Errorf("file %q should be materialized with the default requirer: %v", p, err)
		}
	}
}
