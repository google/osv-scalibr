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
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestOpenRoot(t *testing.T) {
	// Create a temp dir for testing
	tmpDir := t.TempDir()

	// Create a file inside temp dir
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("hello"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	sr, err := scalibrfs.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot failed: %v", err)
	}
	defer sr.OSRoot.Close()

	// Try to open the file via fsys
	f, err := sr.FS.Open("test.txt")
	if err != nil {
		t.Fatalf("Failed to open file via fsys: %v", err)
	}
	defer f.Close()

	// Read content
	content, err := fs.ReadFile(sr.FS, "test.txt")
	if err != nil {
		t.Fatalf("Failed to read file via fsys: %v", err)
	}
	if string(content) != "hello" {
		t.Errorf("Expected 'hello', got %q", string(content))
	}

	// Test sandboxing (should not be able to access files outside)
	// os.Root should prevent this.
	_, err = sr.FS.Open("../outside.txt")
	if err == nil {
		t.Errorf("Expected error when accessing outside file, got nil")
	}
}
