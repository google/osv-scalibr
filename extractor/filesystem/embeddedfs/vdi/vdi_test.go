// Copyright 2025 Google LLC
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

package vdi_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/vdi"
)

func TestFileRequired(t *testing.T) {
	extractor := vdi.New()
	tests := []struct {
		path string
		want bool
	}{
		{"testdata/valid.vdi", true},
		{"testdata/VALID.vdi", true},
		{"testdata/invalid.vdi", true},
		{"testdata/document.txt", false},
		{"testdata/noextension", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			api := &mockFileAPI{path: tt.path}
			if got := extractor.FileRequired(api); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
func TestExtractValidVDI(t *testing.T) {
	extractor := vdi.New()
	path := "testdata/valid.vdi"
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", path, err)
	}
	input := &filesystem.ScanInput{
		Path:   path,
		Root:   ".",
		Info:   info,
		Reader: nil,
		FS:     nil,
	}

	ctx := context.Background()
	inv, err := extractor.Extract(ctx, input)
	if err != nil {
		t.Fatalf("Extract(%q) failed: %v", path, err)
	}

	if len(inv.EmbeddedFSs) == 0 {
		t.Fatal("Extract returned no DiskImages")
	}

	for i, embeddedFS := range inv.EmbeddedFSs {
		t.Run(fmt.Sprintf("DiskImage_%d", i), func(t *testing.T) {
			if !strings.HasPrefix(embeddedFS.Path, path) {
				t.Errorf("EmbeddedFS.Path = %q, want prefix %q", embeddedFS.Path, path)
			}

			fs, _ := embeddedFS.GetEmbeddedFS(ctx)

			entries, err := fs.ReadDir("/")
			if err != nil {
				t.Fatalf("fs.ReadDir(/) failed: %v", err)
			}
			t.Logf("ReadDir(/) returned %d entries", len(entries))

			info, err := fs.Stat("/")
			if err != nil {
				t.Fatalf("fs.Stat(/) failed: %v", err)
			}
			if !info.IsDir() {
				t.Errorf("fs.Stat(/) IsDir() = %v, want true", info.IsDir())
			}

			found := false
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasSuffix(name, ".pem") {
					found = true
					filePath := "/" + name
					f, err := fs.Open(filePath)
					if err != nil {
						t.Fatalf("fs.Open(%q) failed: %v", filePath, err)
					}
					defer f.Close()

					if _, ok := f.(io.ReaderAt); !ok {
						t.Errorf("fs.Open(%q) did not return an io.ReaderAt", filePath)
					}

					buf := make([]byte, 4096)
					n, err := f.Read(buf)
					if err != nil && !errors.Is(err, io.EOF) {
						t.Errorf("f.Read(%q) failed: %v", filePath, err)
					}
					t.Logf("Read %d bytes from %s\n%s", n, name, buf)

					info, err := f.Stat()
					if err != nil {
						t.Errorf("f.Stat(%q) failed: %v", filePath, err)
					} else if info.IsDir() {
						t.Errorf("f.Stat(%q) IsDir() = %v, want false", filePath, info.IsDir())
					}
					break
				}
			}
			if !found {
				t.Errorf("private keys not found")
			}
		})
	}
}

func TestExtractInvalidVDI(t *testing.T) {
	extractor := vdi.New()
	path := "testdata/invalid.vdi"
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", path, err)
	}
	input := &filesystem.ScanInput{
		Path:   path,
		Root:   ".",
		Info:   info,
		Reader: nil,
		FS:     nil,
	}

	ctx := context.Background()
	_, err = extractor.Extract(ctx, input)
	if err == nil {
		t.Errorf("Extract(%q) succeeded, want error", path)
	}
}

func TestExtractNonExistentVDI(t *testing.T) {
	extractor := vdi.New()
	path := "testdata/nonexistent.vdi"
	input := &filesystem.ScanInput{
		Path:   path,
		Root:   "testdata",
		Info:   nil,
		Reader: nil,
		FS:     nil,
	}

	ctx := context.Background()
	_, err := extractor.Extract(ctx, input)
	if err == nil {
		t.Errorf("Extract(%q) succeeded, want error", path)
	}
}

type mockFileAPI struct {
	path string
}

func (m *mockFileAPI) Path() string {
	return m.path
}

func (m *mockFileAPI) Stat() (fs.FileInfo, error) {
	return os.Stat(m.path)
}
