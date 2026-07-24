package common

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createTestZip(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer

	zw := zip.NewWriter(&buf)

	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %q: %v", name, err)
		}

		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry %q: %v", name, err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	return &buf
}

func TestZIPToTempDir(t *testing.T) {
	tests := []struct {
		name         string
		files        map[string]string
		maxFileSize  int64
		expectedFile string
		expectedData string
		skippedFile  string
	}{
		{
			name: "extract single file",
			files: map[string]string{
				"hello.txt": "hello world",
			},
			maxFileSize:  1024,
			expectedFile: "hello.txt",
			expectedData: "hello world",
		},
		{
			name: "extract nested file",
			files: map[string]string{
				"a/b/c/test.txt": "nested",
			},
			maxFileSize:  1024,
			expectedFile: filepath.Join("a", "b", "c", "test.txt"),
			expectedData: "nested",
		},
		{
			name: "skip file larger than max size",
			files: map[string]string{
				"large.txt": strings.Repeat("A", 2048),
			},
			maxFileSize: 1024,
			skippedFile: "large.txt",
		},
		{
			name:        "empty zip",
			files:       map[string]string{},
			maxFileSize: 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zipData := createTestZip(t, tt.files)

			tempRoot, err := ZIPToTempDir(zipData, tt.maxFileSize)
			if err != nil {
				t.Fatalf("ZIPToTempDir() error = %v", err)
			}
			defer func() {
				tempDir := tempRoot.Name()
				tempRoot.Close()
				os.RemoveAll(tempDir)
			}()

			if tt.expectedFile != "" {
				data, err := tempRoot.ReadFile(tt.expectedFile)
				if err != nil {
					t.Fatalf("failed to read extracted file: %v", err)
				}

				if string(data) != tt.expectedData {
					t.Fatalf(
						"unexpected content: got %q want %q",
						string(data),
						tt.expectedData,
					)
				}
			}

			if tt.skippedFile != "" {
				_, err := tempRoot.Stat(tt.skippedFile)
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf(
						"expected %q to be skipped, got err=%v",
						tt.skippedFile,
						err,
					)
				}
			}
		})
	}
}

func TestZIPToTempDir_PathTraversal(t *testing.T) {
	var buf bytes.Buffer

	zw := zip.NewWriter(&buf)

	w, err := zw.Create("../evil.txt")
	if err != nil {
		t.Fatalf("failed to create zip entry: %v", err)
	}

	if _, err := w.Write([]byte("evil")); err != nil {
		t.Fatalf("failed to write zip entry: %v", err)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	_, err = ZIPToTempDir(&buf, 1024)
	if err == nil {
		t.Fatal("expected path traversal error")
	}
}
