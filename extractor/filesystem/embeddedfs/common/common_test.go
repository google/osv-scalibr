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

package common

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
)

const (
	fileName     = "50_mb_sparse_file_actual_size_1mb.bin"
	logicalSize  = 50 * units.MiB
	realDataSize = 1 * units.MiB
)

func createSparseTAR(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: fileName,
		Mode: 0644,
		Size: logicalSize,
	}); err != nil {
		t.Fatalf("tw.WriteHeader: %v", err)
	}
	if _, err := tw.Write(make([]byte, logicalSize-realDataSize)); err != nil {
		t.Fatalf("tw.Write zeroes: %v", err)
	}
	if _, err := tw.Write(bytes.Repeat([]byte("A"), int(realDataSize))); err != nil {
		t.Fatalf("tw.Write payload: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	return &buf
}

func TestTARToTempDir(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("TARToTempDir tests are only supported on Linux")
	}

	tests := []struct {
		name                   string
		maxFreeSpaceUsageRatio float64
		wantErr                string
	}{
		{
			name: "sparse file extracted without full physical allocation",
			// Assumes CI machine temp storage > 1 MiB / 0.8 = 1.25 MiB.
			maxFreeSpaceUsageRatio: 0.8,
		},
		{
			name: "exceeds TMPFS size raises error instead of OOM",
			// Assumes CI machine temp storage < 1 MiB / 1e-9 = 1 PB.
			maxFreeSpaceUsageRatio: 1e-9,
			wantErr:                "exceeds allowed temp storage",
		},
		{
			name:                   "ratio zero disables free space check",
			maxFreeSpaceUsageRatio: 0.0,
		},
		{
			name:                   "negative ratio disables free space check",
			maxFreeSpaceUsageRatio: -0.5,
		},
		{
			name:                   "ratio above one disables free space check",
			maxFreeSpaceUsageRatio: 1.5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tempDir, err := TARToTempDir(createSparseTAR(t), tc.maxFreeSpaceUsageRatio)
			defer os.RemoveAll(tempDir)

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("TARToTempDir() error = %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("TARToTempDir() unexpected error: %v", err)
			}

			fi, err := os.Stat(filepath.Join(tempDir, fileName))
			if err != nil || fi.Size() != logicalSize {
				t.Fatalf("os.Stat(%q) size = %v (err = %v), want %d", fileName, fi.Size(), err, logicalSize)
			}

			if alloc, err := fileAllocatedBytes(fi); err != nil || (alloc >= 0 && alloc > realDataSize*12/10) {
				t.Errorf("allocated disk bytes = %d (err = %v), want <= %d", alloc, err, realDataSize*12/10)
			}
		})
	}
}

func TestCalcMaxAllowedBytes(t *testing.T) {
	tests := []struct {
		name      string
		freeBytes int64
		ratio     float64
		want      int64
	}{
		{
			name:      "valid ratio 0.8",
			freeBytes: 1000,
			ratio:     0.8,
			want:      800,
		},
		{
			name:      "valid upper boundary ratio 1.0",
			freeBytes: 1000,
			ratio:     1.0,
			want:      1000,
		},
		{
			name:      "ratio zero disables",
			freeBytes: 1000,
			ratio:     0.0,
			want:      0,
		},
		{
			name:      "negative ratio disables",
			freeBytes: 1000,
			ratio:     -0.5,
			want:      0,
		},
		{
			name:      "ratio above one disables",
			freeBytes: 1000,
			ratio:     1.5,
			want:      0,
		},
		{
			name:      "zero free bytes",
			freeBytes: 0,
			ratio:     0.8,
			want:      0,
		},
		{
			name:      "negative free bytes",
			freeBytes: -100,
			ratio:     0.8,
			want:      0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := calcMaxAllowedBytes(tc.freeBytes, tc.ratio); got != tc.want {
				t.Errorf("calcMaxAllowedBytes(%d, %f) = %d, want %d", tc.freeBytes, tc.ratio, got, tc.want)
			}
		})
	}
}

func TestIsZero(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want bool
	}{
		{"empty", []byte{}, true},
		{"all zeros", make([]byte, 100), true},
		{"non-zero at start", []byte{1, 0, 0}, false},
		{"non-zero at end", []byte{0, 0, 1}, false},
		{"non-zero in middle", []byte{0, 2, 0}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isZero(tc.buf); got != tc.want {
				t.Errorf("isZero(%v) = %v, want %v", tc.buf, got, tc.want)
			}
		})
	}
}

func TestWriteExtractedFile(t *testing.T) {
	rootDir := t.TempDir()
	outsideDir := t.TempDir()

	if err := os.Symlink(outsideDir, filepath.Join(rootDir, "outlink")); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		t.Fatalf("os.OpenRoot: %v", err)
	}
	defer root.Close()

	t.Run("writes root and nested files", func(t *testing.T) {
		if err := writeExtractedFile(root, "root.txt", strings.NewReader("hello"), 0644, 1024); err != nil {
			t.Fatalf("writeExtractedFile(root.txt) unexpected error: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(rootDir, "root.txt"))
		if err != nil || string(got) != "hello" {
			t.Errorf("ReadFile(root.txt) = %q, %v; want %q, nil", got, err, "hello")
		}

		nestedRel := filepath.Join("a", "b", "nested.txt")
		if err := writeExtractedFile(root, nestedRel, strings.NewReader("world"), 0644, 1024); err != nil {
			t.Fatalf("writeExtractedFile(%q) unexpected error: %v", nestedRel, err)
		}
		got, err = os.ReadFile(filepath.Join(rootDir, nestedRel))
		if err != nil || string(got) != "world" {
			t.Errorf("ReadFile(%q) = %q, %v; want %q, nil", nestedRel, got, err, "world")
		}
	})

	t.Run("bounds write to maxBytes", func(t *testing.T) {
		if err := writeExtractedFile(root, "bounded.txt", strings.NewReader("0123456789"), 0644, 4); err != nil {
			t.Fatalf("writeExtractedFile(bounded.txt) unexpected error: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(rootDir, "bounded.txt"))
		if err != nil || string(got) != "0123" {
			t.Errorf("ReadFile(bounded.txt) = %q, %v; want %q, nil", got, err, "0123")
		}
	})

	escapePaths := []string{
		"../escape.txt",
		filepath.Join("a", "..", "..", "escape.txt"),
		"/escape.txt",
		filepath.Join("outlink", "escape.txt"),
	}
	for _, relPath := range escapePaths {
		t.Run("rejects_"+relPath, func(t *testing.T) {
			if err := writeExtractedFile(root, relPath, strings.NewReader("pwned"), 0644, 1024); err == nil {
				t.Errorf("writeExtractedFile(%q) succeeded, want error", relPath)
			}
			if _, err := os.Stat(filepath.Join(outsideDir, "escape.txt")); !os.IsNotExist(err) {
				t.Errorf("escape.txt created outside root (err = %v)", err)
			}
		})
	}
}

func TestTARToTempDir_PathsAndTraversal(t *testing.T) {
	t.Run("extracts nested directories and dot-prefixed entries", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		entries := []struct {
			hdr  *tar.Header
			body string
		}{
			{hdr: &tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0755}},
			{hdr: &tar.Header{Name: "subdir/", Typeflag: tar.TypeDir, Mode: 0755}},
			{hdr: &tar.Header{Name: "subdir/nested.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: 6}, body: "nested"},
			{hdr: &tar.Header{Name: "./dotfile.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: 3}, body: "dot"},
		}
		for _, e := range entries {
			if err := tw.WriteHeader(e.hdr); err != nil {
				t.Fatalf("tw.WriteHeader(%q): %v", e.hdr.Name, err)
			}
			if e.body != "" {
				if _, err := tw.Write([]byte(e.body)); err != nil {
					t.Fatalf("tw.Write(%q): %v", e.hdr.Name, err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("tw.Close: %v", err)
		}

		tempDir, err := TARToTempDir(&buf, 0)
		if err != nil {
			t.Fatalf("TARToTempDir() unexpected error: %v", err)
		}
		defer os.RemoveAll(tempDir)

		gotNested, err := os.ReadFile(filepath.Join(tempDir, "subdir", "nested.txt"))
		if err != nil || string(gotNested) != "nested" {
			t.Errorf("ReadFile(subdir/nested.txt) = %q, %v; want %q, nil", gotNested, err, "nested")
		}
		gotDot, err := os.ReadFile(filepath.Join(tempDir, "dotfile.txt"))
		if err != nil || string(gotDot) != "dot" {
			t.Errorf("ReadFile(dotfile.txt) = %q, %v; want %q, nil", gotDot, err, "dot")
		}
	})

	t.Run("prevents traversal outside tempDir", func(t *testing.T) {
		const escapeName = "scalibr_tar_escape_test_578012903.txt"
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(&tar.Header{
			Name:     "../" + escapeName,
			Typeflag: tar.TypeReg,
			Mode:     0644,
			Size:     5,
		}); err != nil {
			t.Fatalf("tw.WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte("pwned")); err != nil {
			t.Fatalf("tw.Write: %v", err)
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("tw.Close: %v", err)
		}

		// Whether the tar reader rejects "../" entries or sanitizes them into tempDir,
		// the file must never be written to the parent temp directory.
		tempDir, err := TARToTempDir(&buf, 0)
		if tempDir != "" {
			defer os.RemoveAll(tempDir)
		}
		parentEscapePath := filepath.Join(os.TempDir(), escapeName)
		defer os.Remove(parentEscapePath)
		if _, statErr := os.Stat(parentEscapePath); !os.IsNotExist(statErr) {
			t.Fatalf("traversal entry escaped tempDir to %s (TARToTempDir err = %v, statErr = %v)", parentEscapePath, err, statErr)
		}
	})
}
