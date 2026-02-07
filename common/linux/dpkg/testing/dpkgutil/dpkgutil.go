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

// Package dpkgutil provides test utilities for DPKG annotators.
package dpkgutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SetupDPKGInfo sets up the DPKG info directory based on the supplied filename->content map.
// if createFiles is true it also creates the provided files (files with no extension are marked as executable)
func SetupDPKGInfo(t *testing.T, contents map[string]string, createFiles bool) string {
	t.Helper()

	dir := t.TempDir()

	infoDir := filepath.Join(dir, "var/lib/dpkg/info")
	if err := os.MkdirAll(infoDir, 0777); err != nil {
		t.Fatalf("error creating directory %q: %v", infoDir, err)
	}

	for name, content := range contents {
		listPath := filepath.Join(infoDir, name)

		listFile, err := os.Create(listPath)
		if err != nil {
			t.Fatalf("Error while creating file %q: %v", listPath, err)
		}
		defer listFile.Close()

		for path := range strings.SplitSeq(content, "\n") {
			path, isFolder := strings.CutSuffix(path, "/")

			if _, err := listFile.WriteString(path + "\n"); err != nil {
				t.Fatalf("Error writing creating file %q: %v", listPath, err)
			}

			// create Files only if the provided argument is true
			if !createFiles {
				continue
			}

			fullPath := filepath.Join(dir, path)

			if isFolder {
				if err := os.Mkdir(fullPath, 0777); err != nil {
					t.Fatalf("Error creating directory %q: %v", infoDir, err)
				}
				continue
			}
			perm := os.FileMode(0666)
			if !strings.Contains(fullPath, ".") {
				perm = 0755
			}
			if err := os.WriteFile(fullPath, []byte{}, perm); err != nil {
				t.Fatalf("Error creating file %q: %v", fullPath, err)
			}
		}
	}
	return dir
}
