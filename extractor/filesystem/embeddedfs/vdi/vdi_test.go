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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/vdi"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
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
			if got := extractor.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractValidVDI(t *testing.T) {
	extractor := vdi.New()

	tests := []struct {
		name string
		path string
	}{
		{
			name: "StaticVDI",
			path: filepath.FromSlash("testdata/valid-ext-exfat-fat32-ntfs-static.vdi"),
		},
		{
			name: "DynamicVDI",
			path: filepath.FromSlash("testdata/valid-ext-exfat-fat32-ntfs-dynamic.vdi"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatalf("os.Stat(%q) failed: %v", tt.path, err)
			}

			f, err := os.Open(tt.path)
			if err != nil {
				t.Fatalf("os.Open(%q) failed: %v", tt.path, err)
			}
			defer f.Close()

			input := &filesystem.ScanInput{
				Path:   tt.path,
				Root:   ".",
				Info:   info,
				Reader: f,
				FS:     nil,
			}

			ctx := t.Context()
			inv, err := extractor.Extract(ctx, input)
			if err != nil {
				t.Fatalf("Extract(%q) failed: %v", tt.path, err)
			}

			if len(inv.EmbeddedFSs) == 0 {
				t.Fatal("Extract returned no DiskImages")
			}

			for i, embeddedFS := range inv.EmbeddedFSs {
				t.Run(fmt.Sprintf("DiskImage_%d", i), func(t *testing.T) {
					if !strings.HasPrefix(embeddedFS.Path, tt.path) {
						t.Errorf("EmbeddedFS.Path = %q, want prefix %q", embeddedFS.Path, tt.path)
					}

					fs, err := embeddedFS.GetEmbeddedFS(ctx)
					if err != nil {
						t.Errorf("GetEmbeddedFS() failed: %v", err)
					}

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
							filePath := name
							f, err := fs.Open(filePath)
							if err != nil {
								t.Fatalf("fs.Open(%q) failed: %v", filePath, err)
							}
							defer f.Close()

							buf := make([]byte, 4096)
							n, err := f.Read(buf)
							if err != nil && !errors.Is(err, io.EOF) {
								t.Errorf("f.Read(%q) failed: %v", filePath, err)
							}
							t.Logf("Read %d bytes from %s\n", n, name)

							// The buffer must start with "-----BEGIN"
							if string(buf[:10]) != "-----BEGIN" {
								t.Errorf("%s contains unexpected data!", filePath)
							}

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
		})
	}
}

func TestExtractInvalidVDI(t *testing.T) {
	extractor := vdi.New()
	path := filepath.FromSlash("testdata/invalid.vdi")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", path, err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open(%q) failed: %v", path, err)
	}
	defer f.Close()

	input := &filesystem.ScanInput{
		Path:   path,
		Root:   ".",
		Info:   info,
		Reader: f,
		FS:     nil,
	}

	ctx := t.Context()
	_, err = extractor.Extract(ctx, input)
	if err == nil {
		t.Errorf("Extract(%q) succeeded, want error", path)
	}
}

func TestExtractNonExistentVDI(t *testing.T) {
	extractor := vdi.New()
	path := filepath.FromSlash("testdata/nonexistent.vdi")
	input := &filesystem.ScanInput{
		Path:   path,
		Root:   "testdata",
		Info:   nil,
		Reader: nil,
		FS:     nil,
	}

	ctx := t.Context()
	_, err := extractor.Extract(ctx, input)
	if err == nil {
		t.Errorf("Extract(%q) succeeded, want error", path)
	}
}
