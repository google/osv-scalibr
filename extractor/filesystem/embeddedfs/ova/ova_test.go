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

package ova_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archive/tar"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/ova"
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
			desc: "ova_lowercase",
			path: "testdata/disk.ova",
			want: true,
		},
		{
			desc: "ova_uppercase",
			path: "testdata/DISK.OVA",
			want: true,
		},
		{
			desc: "not_ova",
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
			path:        "disk.ova",
			fileSize:    1000,
			maxFileSize: 1000,
			want:        true,
		},
		{
			desc:        "file_size_above_limit",
			path:        "disk.ova",
			fileSize:    1001,
			maxFileSize: 1000,
			want:        false,
		},
		{
			desc:                  "override_global_size_below_limit",
			path:                  "disk.ova",
			fileSize:              1001,
			maxFileSize:           1000,
			pluginSpecificMaxSize: 1001,
			want:                  true,
		},
		{
			desc:                  "override_global_size_above_limit",
			path:                  "disk.ova",
			fileSize:              1001,
			maxFileSize:           1001,
			pluginSpecificMaxSize: 1000,
			want:                  false,
		},
	}

	for _, tt := range tests {
		extractor, err := ova.New(&cpb.PluginConfig{
			MaxFileSizeBytes: tt.maxFileSize,
			PluginSpecific: []*cpb.PluginSpecificConfig{
				{Config: &cpb.PluginSpecificConfig_Ova{Ova: &cpb.OVAConfig{MaxFileSizeBytes: tt.pluginSpecificMaxSize}}},
			},
		})
		if err != nil {
			t.Fatalf("ova.New: %v", err)
		}
		t.Run(tt.desc, func(t *testing.T) {
			if got := extractor.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileSize: tt.fileSize,
			})); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractValidOVA(t *testing.T) {
	extractor, err := ova.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("ova.New: %v", err)
	}
	path := filepath.FromSlash("testdata/valid.ova")
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
	inv, err := extractor.Extract(ctx, input)
	if err != nil {
		t.Fatalf("Extract(%q) failed: %v", path, err)
	}

	if len(inv.EmbeddedFSs) == 0 {
		t.Fatal("Extract returned nothing")
	}

	for i, embeddedFS := range inv.EmbeddedFSs {
		t.Run(fmt.Sprintf("OVAImage_%d", i), func(t *testing.T) {
			if !strings.HasPrefix(embeddedFS.Path, path) {
				t.Errorf("EmbeddedFS.Path = %q, want prefix %q", embeddedFS.Path, path)
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
				if strings.HasSuffix(name, ".ovf") {
					found = true
					filePath := name
					f, err := fs.Open(filePath)
					if err != nil {
						t.Fatalf("fs.Open(%q) failed: %v", filePath, err)
					}
					defer f.Close()

					buf := make([]byte, 5)
					n, err := f.Read(buf)
					if err != nil && !errors.Is(err, io.EOF) {
						t.Errorf("f.Read(%q) failed: %v", filePath, err)
					}
					t.Logf("Read %d bytes from %s\n", n, name)

					// The buffer must start with "<?xml"
					if string(buf[:5]) != "<?xml" {
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
				t.Errorf("ovf file not found")
			}
		})
	}
}

func TestExtractMaliciousOVA(t *testing.T) {
	// Create a malicious tar archive in memory
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Create a header with "../../../../../../../../../file.txt"
	// to simulate a path traversal entry
	hdr := &tar.Header{
		Name:     "../../../../../../../../../file.txt",
		Mode:     0600,
		Size:     int64(len("malicious content")),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}
	if _, err := tw.Write([]byte("malicious content")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	tw.Close()

	extractor, err := ova.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("ova.New: %v", err)
	}
	input := &filesystem.ScanInput{
		Path:   "",
		Root:   "testdata",
		Info:   nil,
		Reader: bytes.NewReader(buf.Bytes()), // provide the in-memory tar data
		FS:     nil,
	}

	ctx := t.Context()
	_, err = extractor.Extract(ctx, input)
	if err == nil {
		t.Errorf("Extract succeeded, want error for parent path entry")
	} else if !strings.Contains(err.Error(), "invalid entries") {
		t.Errorf("Extract error = %v, want 'invalid entries'", err)
	}
}

func TestExtractInvalidOVA(t *testing.T) {
	extractor, err := ova.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("ova.New: %v", err)
	}
	path := filepath.FromSlash("testdata/invalid.ova")
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

func TestExtractNonExistentOVA(t *testing.T) {
	extractor, err := ova.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("ova.New: %v", err)
	}
	path := filepath.FromSlash("testdata/nonexistent.ova")
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
