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

func TestTARToTempDirRejectsNonLocalEntries(t *testing.T) {
	// Keep even a vulnerable extraction confined to a test-owned directory.
	tempBase := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, tempBase)
	}
	const payload = "archive payload"
	tests := []struct {
		name        string
		entry       string
		windowsOnly bool
	}{
		{name: "parent", entry: "../outside"},
		{name: "nested_parent", entry: "nested/../../outside"},
		{name: "absolute", entry: filepath.Join(tempBase, "outside")},
		{name: "backslash_parent", entry: `..\outside`, windowsOnly: true},
		{name: "backslash_nested", entry: `nested\..\..\outside`, windowsOnly: true},
		{name: "mixed_separators", entry: `nested/..\..\outside`, windowsOnly: true},
		{name: "drive_relative", entry: `C:outside`, windowsOnly: true},
		{name: "reserved_device", entry: "NUL", windowsOnly: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.windowsOnly && runtime.GOOS != "windows" {
				t.Skip("entry is non-local only on Windows")
			}
			for _, typeflag := range []byte{tar.TypeReg, tar.TypeDir} {
				t.Run(string(typeflag), func(t *testing.T) {
					outside := filepath.Join(tempBase, "outside")
					const sentinel = "existing file"
					if typeflag == tar.TypeReg {
						if err := os.WriteFile(outside, []byte(sentinel), 0600); err != nil {
							t.Fatal(err)
						}
						defer os.Remove(outside)
					}
					var buf bytes.Buffer
					tw := tar.NewWriter(&buf)
					hdr := &tar.Header{Name: tc.entry, Typeflag: typeflag, Mode: 0755}
					if typeflag == tar.TypeReg {
						hdr.Size = int64(len(payload))
					}
					if err := tw.WriteHeader(hdr); err != nil {
						t.Fatal(err)
					}
					if typeflag == tar.TypeReg {
						if _, err := tw.Write([]byte(payload)); err != nil {
							t.Fatal(err)
						}
					}
					if err := tw.Close(); err != nil {
						t.Fatal(err)
					}
					dir, err := TARToTempDir(&buf, 0)
					if dir != "" {
						defer os.RemoveAll(dir)
						t.Errorf("TARToTempDir() returned directory %q", dir)
					}
					if err == nil || !strings.Contains(err.Error(), "tar contains invalid entries") {
						t.Errorf("TARToTempDir() error = %v, want invalid entries", err)
					}
					if typeflag == tar.TypeReg {
						got, err := os.ReadFile(outside)
						if err != nil || string(got) != sentinel {
							t.Errorf("outside file = %q, error = %v; want %q", got, err, sentinel)
						}
					} else if _, err := os.Stat(outside); !os.IsNotExist(err) {
						t.Errorf("outside directory stat error = %v, want not exist", err)
					}
					leftovers, err := filepath.Glob(filepath.Join(tempBase, "scalibr-archive-*"))
					if err != nil || len(leftovers) != 0 {
						t.Errorf("extraction directories = %v, error = %v; want none", leftovers, err)
					}
				})
			}
		})
	}
}

func TestTARToTempDirLocalEntries(t *testing.T) {
	entries := []struct{ name, entry string }{
		{"file", "file.txt"},
		{"nested", "nested/file.txt"},
		{"dot_prefix", "./nested/file.txt"},
		{"local_parent", "nested/../file.txt"},
	}
	if runtime.GOOS != "windows" {
		// Backslashes are literal filename characters on Unix.
		entries = append(entries, struct{ name, entry string }{"literal_backslash", `..\file.txt`})
	}
	for _, tc := range entries {
		t.Run(tc.name, func(t *testing.T) {
			const payload = "archive payload"
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			if err := tw.WriteHeader(&tar.Header{Name: tc.entry, Mode: 0600, Size: int64(len(payload))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			dir, err := TARToTempDir(&buf, 0)
			if err != nil {
				t.Fatalf("TARToTempDir() error = %v", err)
			}
			defer os.RemoveAll(dir)
			got, err := os.ReadFile(filepath.Join(dir, tc.entry))
			if err != nil || string(got) != payload {
				t.Errorf("extracted file = %q, error = %v; want %q", got, err, payload)
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
