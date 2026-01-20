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

package qcow2_test

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/qcow2"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		desc                  string
		path                  string
		fileSize              int64
		maxFileSize           int64
		pluginSpecificMaxSize int64
		want                  bool
	}{
		{
			desc: "vmdk_lowercase",
			path: "testdata/disk.qcow2",
			want: true,
		},
		{
			desc: "vmdk_uppercase",
			path: "testdata/DISK.QCOW2",
			want: true,
		},
		{
			desc: "not_vmdk",
			path: "testdata/document.txt",
			want: false,
		},
		{
			desc: "no_extension",
			path: "testdata/noextension",
			want: false,
		},
		{
			desc:        "file_size_below_limit",
			path:        "disk.qcow2",
			fileSize:    1000,
			maxFileSize: 1000,
			want:        true,
		},
		{
			desc:        "file_size_above_limit",
			path:        "disk.qcow2",
			fileSize:    1001,
			maxFileSize: 1000,
			want:        false,
		},
		{
			desc:                  "override_global_size_below_limit",
			path:                  "disk.qcow2",
			fileSize:              1001,
			maxFileSize:           1000,
			pluginSpecificMaxSize: 1001,
			want:                  true,
		},
		{
			desc:                  "override_global_size_above_limit",
			path:                  "disk.qcow2",
			fileSize:              1001,
			maxFileSize:           1001,
			pluginSpecificMaxSize: 1000,
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			extractor, err := qcow2.New(&cpb.PluginConfig{
				MaxFileSizeBytes: tt.maxFileSize,
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{Config: &cpb.PluginSpecificConfig_Qcow2{Qcow2: &cpb.QCOW2Config{MaxFileSizeBytes: tt.pluginSpecificMaxSize}}},
				},
			})
			if err != nil {
				t.Fatalf("qcow2.New: %v", err)
			}
			if got := extractor.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileSize: tt.fileSize,
			})); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractValidQCOW2(t *testing.T) {
	extractor, err := qcow2.New(&cpb.PluginConfig{
		PluginSpecific: []*cpb.PluginSpecificConfig{
			{Config: &cpb.PluginSpecificConfig_Qcow2{Qcow2: &cpb.QCOW2Config{Password: "Yuvraj"}}},
		},
	})
	if err != nil {
		t.Fatalf("qcow2.New: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{
			name: "qcow2",
			path: filepath.FromSlash("testdata/valid-ext-exfat-fat32-ntfs.qcow2"),
		},
		{
			name: "Encrypted qcow2",
			path: filepath.FromSlash("testdata/valid-ext-exfat-fat32-ntfs-encrypted.qcow2"),
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
				t.Run(fmt.Sprintf("Partition_%d", i+1), func(t *testing.T) {
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

func TestExtractInvalidQCOW2(t *testing.T) {
	extractor, err := qcow2.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("qcow2.New: %v", err)
	}

	path := filepath.FromSlash("testdata/invalid.qcow2")
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

func TestExtractNonExistentQCOW2(t *testing.T) {
	extractor, err := qcow2.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("qcow2.New: %v", err)
	}

	path := filepath.FromSlash("testdata/nonexistent.qcow2")
	input := &filesystem.ScanInput{
		Path:   path,
		Root:   "testdata",
		Info:   nil,
		Reader: nil,
		FS:     nil,
	}

	ctx := t.Context()
	_, err = extractor.Extract(ctx, input)
	if err == nil {
		t.Errorf("Extract(%q) succeeded, want error", path)
	}
}
