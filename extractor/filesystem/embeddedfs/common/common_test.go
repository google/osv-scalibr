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
	"www.velocidex.com/golang/go-ntfs/parser"
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

func createTarWithHeader(t *testing.T, header *tar.Header, content []byte) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("tw.WriteHeader: %v", err)
	}
	if len(content) > 0 {
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("tw.Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	return &buf
}

func TestTARToTempDir_InvalidEntries(t *testing.T) {
	tests := []struct {
		name    string
		hdrName string
		wantErr bool
	}{
		{
			name:    "valid relative path",
			hdrName: "dir/valid.txt",
			wantErr: false,
		},
		{
			name:    "valid dot slash path",
			hdrName: "./valid.txt",
			wantErr: false,
		},
		{
			name:    "parent directory traversal slash",
			hdrName: "../evil.txt",
			wantErr: true,
		},
		{
			name:    "nested parent directory traversal slash",
			hdrName: "dir/../../evil.txt",
			wantErr: true,
		},
		{
			name:    "parent directory traversal backslash",
			hdrName: `..\evil.txt`,
			wantErr: true,
		},
		{
			name:    "nested parent directory traversal backslash",
			hdrName: `dir\..\..\evil.txt`,
			wantErr: true,
		},
		{
			name:    "absolute path slash",
			hdrName: "/etc/passwd",
			wantErr: true,
		},
		{
			name:    "absolute path backslash",
			hdrName: `\Windows\system.ini`,
			wantErr: true,
		},
		{
			name:    "drive letter path",
			hdrName: `C:\evil.txt`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := createTarWithHeader(t, &tar.Header{
				Name:     tc.hdrName,
				Mode:     0644,
				Size:     int64(len("test")),
				Typeflag: tar.TypeReg,
			}, []byte("test"))

			tempDir, err := TARToTempDir(buf, 0.0)
			if tempDir != "" {
				defer os.RemoveAll(tempDir)
			}

			if tc.wantErr {
				if err == nil {
					t.Fatalf("TARToTempDir(%q) expected error, got nil", tc.hdrName)
				}
				if !strings.Contains(err.Error(), "tar contains invalid entries") {
					t.Errorf("TARToTempDir(%q) error = %v, want error containing 'tar contains invalid entries'", tc.hdrName, err)
				}
			} else if err != nil {
				t.Fatalf("TARToTempDir(%q) unexpected error: %v", tc.hdrName, err)
			}
		})
	}
}

func TestFilterEntries(t *testing.T) {
	t.Run("filterEntriesNtfs", func(t *testing.T) {
		entries := []*parser.FileInfo{
			{Name: "valid.txt"},
			{Name: "dir/traversal.txt"},
			{Name: `dir\traversal.txt`},
			{Name: "$MFT"},
			{Name: "."},
			{Name: ".."},
		}
		filtered := filterEntriesNtfs(entries)
		if len(filtered) != 1 || filtered[0].Name != "valid.txt" {
			t.Errorf("filterEntriesNtfs() = %v, want only valid.txt", filtered)
		}
	})

	t.Run("filterEntriesFat32", func(t *testing.T) {
		entries := []os.FileInfo{
			&fileInfo{name: "valid.txt"},
			&fileInfo{name: "dir/traversal.txt"},
			&fileInfo{name: `dir\traversal.txt`},
			&fileInfo{name: "lost+found"},
			&fileInfo{name: "."},
			&fileInfo{name: ".."},
		}
		filtered := filterEntriesFat32(entries)
		if len(filtered) != 1 || filtered[0].Name() != "valid.txt" {
			t.Errorf("filterEntriesFat32() = %v, want only valid.txt", filtered)
		}
	})

	t.Run("isInvalidEntry", func(t *testing.T) {
		invalidCases := []string{"", ".", "..", "$sys", "a/b", `a\b`}
		for _, c := range invalidCases {
			if !isInvalidEntry(c) {
				t.Errorf("isInvalidEntry(%q) = false, want true", c)
			}
		}
		validCases := []string{"foo.txt", "valid_name", "archive.tar"}
		for _, c := range validCases {
			if isInvalidEntry(c) {
				t.Errorf("isInvalidEntry(%q) = true, want false", c)
			}
		}
	})
}
