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

package image

import (
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	rootDirectory = &virtualFile{
		extractDir:  "/tmp/extract",
		layerDir:    "layer1",
		virtualPath: "/",
		isWhiteout:  false,
		mode:        fs.ModeDir | dirPermission,
	}
	rootFile = &virtualFile{
		extractDir:  "/tmp/extract",
		layerDir:    "layer1",
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
	}
	nonRootDirectory = &virtualFile{
		extractDir:  "/tmp/extract",
		layerDir:    "layer1",
		virtualPath: "/dir1/dir2",
		isWhiteout:  false,
		mode:        fs.ModeDir | dirPermission,
	}
	nonRootFile = &virtualFile{
		extractDir:  "/tmp/extract",
		layerDir:    "layer1",
		virtualPath: "/dir1/foo",
		isWhiteout:  false,
		mode:        filePermission,
	}
)

// TODO: b/377551664 - Add tests for the Stat method for the virtualFile type.
func TestStat(t *testing.T) {
	baseTime := time.Now()
	regularVirtualFile := &virtualFile{
		extractDir:  "tempDir",
		layerDir:    "",
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
		size:        1,
		modTime:     baseTime,
	}
	symlinkVirtualFile := &virtualFile{
		extractDir:  "tempDir",
		layerDir:    "",
		virtualPath: "/symlink-to-bar",
		targetPath:  "/bar",
		isWhiteout:  false,
		mode:        fs.ModeSymlink | filePermission,
		size:        1,
		modTime:     baseTime,
	}
	whiteoutVirtualFile := &virtualFile{
		extractDir:  "tempDir",
		layerDir:    "",
		virtualPath: "/bar",
		isWhiteout:  true,
		mode:        filePermission,
	}

	type info struct {
		name    string
		size    int64
		mode    fs.FileMode
		modTime time.Time
	}

	tests := []struct {
		name     string
		node     *virtualFile
		wantInfo info
		wantErr  error
	}{
		{
			name: "regular file",
			node: regularVirtualFile,
			wantInfo: info{
				name:    "bar",
				size:    1,
				mode:    filePermission,
				modTime: baseTime,
			},
		},
		{
			name: "symlink",
			node: symlinkVirtualFile,
			wantInfo: info{
				name:    "symlink-to-bar",
				size:    1,
				mode:    fs.ModeSymlink | filePermission,
				modTime: baseTime,
			},
		},
		{
			name:    "whiteout file",
			node:    whiteoutVirtualFile,
			wantErr: fs.ErrNotExist,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVirtualFile, gotErr := tc.node.Stat()
			if tc.wantErr != nil {
				if diff := cmp.Diff(tc.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
					t.Errorf("Stat(%v) returned unexpected error (-want +got): %v", tc.node, diff)
				}
				return
			}

			gotInfo := info{
				name:    gotVirtualFile.Name(),
				size:    gotVirtualFile.Size(),
				mode:    gotVirtualFile.Mode(),
				modTime: gotVirtualFile.ModTime(),
			}
			if diff := cmp.Diff(tc.wantInfo, gotInfo, cmp.AllowUnexported(info{})); diff != "" {
				t.Errorf("Stat(%v) returned unexpected virtualFile (-want +got): %v", tc.node, diff)
			}
		})
	}
}

func TestRead(t *testing.T) {
	const bufferSize = 20

	tempDir := t.TempDir()
	_ = os.WriteFile(path.Join(tempDir, "bar"), []byte("bar"), 0600)

	_ = os.WriteFile(path.Join(tempDir, "baz"), []byte("baz"), 0600)
	openedRootFile, err := os.OpenFile(path.Join(tempDir, "baz"), os.O_RDONLY, filePermission)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	// Close the file after the test. The file should be closed via the virtualFile.Close method,
	// however, this test explicitly closes the file since the virtualFile.Close method is tested in a
	// separate test.
	defer openedRootFile.Close()

	_ = os.MkdirAll(path.Join(tempDir, "dir1"), 0700)
	_ = os.WriteFile(path.Join(tempDir, "dir1/foo"), []byte("foo"), 0600)

	unopenedVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
	}
	openedVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/baz",
		isWhiteout:  false,
		mode:        filePermission,
		file:        openedRootFile,
	}
	nonRootVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/dir1/foo",
		isWhiteout:  false,
		mode:        filePermission,
	}
	nonexistentVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/dir1/xyz",
		isWhiteout:  false,
		mode:        filePermission,
	}
	whiteoutVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/dir1/abc",
		isWhiteout:  true,
		mode:        filePermission,
	}
	tests := []struct {
		name    string
		node    *virtualFile
		want    string
		wantErr bool
	}{
		{
			name: "unopened root file",
			node: unopenedVirtualFile,
			want: "bar",
		},
		{
			name: "opened root file",
			node: openedVirtualFile,
			want: "baz",
		},
		{
			name: "non-root file",
			node: nonRootVirtualFile,
			want: "foo",
		},
		{
			name:    "nonexistent file",
			node:    nonexistentVirtualFile,
			wantErr: true,
		},
		{
			name:    "whiteout file",
			node:    whiteoutVirtualFile,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotBytes := make([]byte, bufferSize)
			gotNumBytesRead, gotErr := tc.node.Read(gotBytes)

			if gotErr != nil {
				if tc.wantErr {
					return
				}
				t.Fatalf("Read(%v) returned error: %v", tc.node, gotErr)
			}

			gotContent := string(gotBytes[:gotNumBytesRead])
			if gotContent != tc.want {
				t.Errorf("Read(%v) = %v, want: %v", tc.node, gotContent, tc.want)
			}

			// Close the file. The Close method is tested in a separate test.
			_ = tc.node.Close()
		})
	}
}

func TestReadAt(t *testing.T) {
	const bufferSize = 20

	tempDir := t.TempDir()
	_ = os.WriteFile(path.Join(tempDir, "bar"), []byte("bar"), 0600)

	_ = os.WriteFile(path.Join(tempDir, "baz"), []byte("baz"), 0600)
	openedRootFile, err := os.OpenFile(path.Join(tempDir, "baz"), os.O_RDONLY, filePermission)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	// Close the file after the test. The file should be closed via the virtualFile.Close method,
	// however, this test explicitly closes the file since the virtualFile.Close method is tested in a
	// separate test.
	defer openedRootFile.Close()

	_ = os.MkdirAll(path.Join(tempDir, "dir1"), 0700)
	_ = os.WriteFile(path.Join(tempDir, "dir1/foo"), []byte("foo"), 0600)

	unopenedVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
	}
	openedVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/baz",
		isWhiteout:  false,
		mode:        filePermission,
		file:        openedRootFile,
	}
	nonRootVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/dir1/foo",
		isWhiteout:  false,
		mode:        filePermission,
	}
	nonexistentVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/dir1/xyz",
		isWhiteout:  false,
		mode:        filePermission,
	}
	whiteoutVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/dir1/abc",
		isWhiteout:  true,
		mode:        filePermission,
	}
	tests := []struct {
		name    string
		node    *virtualFile
		offset  int64
		want    string
		wantErr error
	}{
		{
			name: "unopened root file",
			node: unopenedVirtualFile,
			want: "bar",
			// All successful reads should return EOF
			wantErr: io.EOF,
		},
		{
			name:    "opened root file",
			node:    openedVirtualFile,
			want:    "baz",
			wantErr: io.EOF,
		},
		{
			name:    "opened root file at offset",
			node:    unopenedVirtualFile,
			offset:  2,
			want:    "r",
			wantErr: io.EOF,
		},
		{
			name:    "opened root file at offset at the end of file",
			node:    unopenedVirtualFile,
			offset:  3,
			want:    "",
			wantErr: io.EOF,
		},
		{
			name:    "opened root file at offset beyond the end of file",
			node:    unopenedVirtualFile,
			offset:  4,
			want:    "",
			wantErr: io.EOF,
		},
		{
			name:    "non-root file",
			node:    nonRootVirtualFile,
			want:    "foo",
			wantErr: io.EOF,
		},
		{
			name:    "non-root file at offset",
			node:    nonRootVirtualFile,
			offset:  1,
			want:    "oo",
			wantErr: io.EOF,
		},
		{
			name:    "nonexistent file",
			node:    nonexistentVirtualFile,
			wantErr: os.ErrNotExist,
		},
		{
			name:    "whiteout file",
			node:    whiteoutVirtualFile,
			wantErr: os.ErrNotExist,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotBytes := make([]byte, bufferSize)
			gotNumBytesRead, gotErr := tc.node.ReadAt(gotBytes, tc.offset)
			// Close the file. The Close method is tested in a separate test.
			defer tc.node.Close()

			if diff := cmp.Diff(tc.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("ReadAt(%v) returned unexpected error (-want +got): %v", tc.node, diff)
				return
			}

			gotContent := string(gotBytes[:gotNumBytesRead])
			if gotContent != tc.want {
				t.Errorf("ReadAt(%v) = %v, want: %v", tc.node, gotContent, tc.want)
			}
		})
	}
}

// Test for the Seek method
func TestSeek(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.WriteFile(path.Join(tempDir, "bar"), []byte("bar"), 0600)

	// Test seeking to different positions
	tests := []struct {
		name   string
		offset int64
		whence int
		want   int64
	}{
		{
			name:   "seek to beginning",
			offset: 0,
			whence: io.SeekStart,
			want:   0,
		},
		{
			name:   "seek to current position",
			offset: 0,
			whence: io.SeekCurrent,
			want:   0,
		},
		{
			name:   "seek to end",
			offset: 0,
			whence: io.SeekEnd,
			want:   3,
		},
		{
			name:   "seek to 10 bytes from beginning",
			offset: 10,
			whence: io.SeekStart,
			want:   10,
		},
		{
			name:   "seek to 10 bytes from current position (at 0)",
			offset: 10,
			whence: io.SeekCurrent,
			want:   10,
		},
		{
			name:   "seek to 2 bytes from end",
			offset: -2,
			whence: io.SeekEnd,
			want:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a virtualFile for the opened file
			virtualFile := &virtualFile{
				extractDir:  tempDir,
				layerDir:    "",
				virtualPath: "/bar",
				isWhiteout:  false,
				mode:        filePermission,
			}
			gotPos, err := virtualFile.Seek(tc.offset, tc.whence)
			_ = virtualFile.Close()
			if err != nil {
				t.Fatalf("Seek failed: %v", err)
			}
			if gotPos != tc.want {
				t.Errorf("Seek returned incorrect position: got %d, want %d", gotPos, tc.want)
			}
		})
	}
}

func TestClose(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.WriteFile(path.Join(tempDir, "bar"), []byte("bar"), 0600)

	unopenedVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
	}
	nonexistentVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/dir1/xyz",
		isWhiteout:  false,
		mode:        filePermission,
	}

	tests := []struct {
		name string
		node *virtualFile
	}{
		{
			name: "unopened root file",
			node: unopenedVirtualFile,
		},
		{
			name: "nonexistent file",
			node: nonexistentVirtualFile,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotErr := tc.node.Close()

			if gotErr != nil {
				t.Fatalf("Read(%v) returned error: %v", tc.node, gotErr)
			}
		})
	}
}

func TestReadingAfterClose(t *testing.T) {
	const bufferSize = 20
	const readAndCloseEvents = 2

	tempDir := t.TempDir()
	_ = os.WriteFile(path.Join(tempDir, "bar"), []byte("bar"), 0600)
	_ = os.WriteFile(path.Join(tempDir, "baz"), []byte("baz"), 0600)
	openedRootFile, err := os.OpenFile(path.Join(tempDir, "baz"), os.O_RDONLY, filePermission)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}

	unopenedVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
	}
	openedVirtualFile := &virtualFile{
		extractDir:  tempDir,
		layerDir:    "",
		virtualPath: "/baz",
		isWhiteout:  false,
		mode:        filePermission,
		file:        openedRootFile,
	}

	tests := []struct {
		name    string
		node    *virtualFile
		want    string
		wantErr bool
	}{
		{
			name: "unopened root file",
			node: unopenedVirtualFile,
			want: "bar",
		},
		{
			name: "opened root file",
			node: openedVirtualFile,
			want: "baz",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for range readAndCloseEvents {
				gotBytes := make([]byte, bufferSize)
				gotNumBytesRead, gotErr := tc.node.Read(gotBytes)

				if gotErr != nil {
					if tc.wantErr {
						return
					}
					t.Fatalf("Read(%v) returned error: %v", tc.node, gotErr)
				}

				gotContent := string(gotBytes[:gotNumBytesRead])
				if gotContent != tc.want {
					t.Errorf("Read(%v) = %v, want: %v", tc.node, gotContent, tc.want)
				}

				err = tc.node.Close()
				if err != nil {
					t.Fatalf("Close(%v) returned error: %v", tc.node, err)
				}
			}
		})
	}
}

func TestRealFilePath(t *testing.T) {
	tests := []struct {
		name string
		node *virtualFile
		want string
	}{
		{
			name: "root directory",
			node: rootDirectory,
			want: filepath.FromSlash("/tmp/extract/layer1"),
		},
		{
			name: "root file",
			node: rootFile,
			want: filepath.FromSlash("/tmp/extract/layer1/bar"),
		},
		{
			name: "non-root file",
			node: nonRootFile,
			want: filepath.FromSlash("/tmp/extract/layer1/dir1/foo"),
		},
		{
			name: "non-root directory",
			node: nonRootDirectory,
			want: filepath.FromSlash("/tmp/extract/layer1/dir1/dir2"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.RealFilePath()
			if got != tc.want {
				t.Errorf("RealFilePath(%v) = %v, want: %v", tc.node, got, tc.want)
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name string
		node *virtualFile
		want string
	}{
		{
			name: "root directory",
			node: rootDirectory,
			want: "",
		},
		{
			name: "root file",
			node: rootFile,
			want: "bar",
		},
		{
			name: "non-root file",
			node: nonRootFile,
			want: "foo",
		},
		{
			name: "non-root directory",
			node: nonRootDirectory,
			want: "dir2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.Name()
			if got != tc.want {
				t.Errorf("Name(%v) = %v, want: %v", tc.node, got, tc.want)
			}
		})
	}
}

func TestIsDir(t *testing.T) {
	tests := []struct {
		name string
		node *virtualFile
		want bool
	}{
		{
			name: "root directory",
			node: rootDirectory,
			want: true,
		},
		{
			name: "root file",
			node: rootFile,
			want: false,
		},
		{
			name: "non-root file",
			node: nonRootFile,
			want: false,
		},
		{
			name: "non-root directory",
			node: nonRootDirectory,
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.IsDir()
			if got != tc.want {
				t.Errorf("IsDir(%v) = %v, want: %v", tc.node, got, tc.want)
			}
		})
	}
}

func TestType(t *testing.T) {
	tests := []struct {
		name string
		node *virtualFile
		want fs.FileMode
	}{
		{
			name: "root directory",
			node: rootDirectory,
			want: fs.ModeDir | dirPermission,
		},
		{
			name: "root file",
			node: rootFile,
			want: filePermission,
		},
		{
			name: "non-root file",
			node: nonRootFile,
			want: filePermission,
		},
		{
			name: "non-root directory",
			node: nonRootDirectory,
			want: fs.ModeDir | dirPermission,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.Type()
			if got != tc.want {
				t.Errorf("Type(%v) = %v, want: %v", tc.node, got, tc.want)
			}
		})
	}
}
