// Copyright 2024 Google LLC
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
	"io/fs"
	"os"
	"path"
	"testing"
)

var (
	rootDirectory = &fileNode{
		extractDir:    "/tmp/extract",
		originLayerID: "layer1",
		virtualPath:   "/",
		isWhiteout:    false,
		mode:          fs.ModeDir | dirPermission,
	}
	rootFile = &fileNode{
		extractDir:    "/tmp/extract",
		originLayerID: "layer1",
		virtualPath:   "/bar",
		isWhiteout:    false,
		mode:          filePermission,
	}
	nonRootDirectory = &fileNode{
		extractDir:    "/tmp/extract",
		originLayerID: "layer1",
		virtualPath:   "/dir1/dir2",
		isWhiteout:    false,
		mode:          fs.ModeDir | dirPermission,
	}
	nonRootFile = &fileNode{
		extractDir:    "/tmp/extract",
		originLayerID: "layer1",
		virtualPath:   "/dir1/foo",
		isWhiteout:    false,
		mode:          filePermission,
	}
)

// TODO: b/377551664 - Add tests for the Stat method for the fileNode type.
func TestStat(t *testing.T) {
	return
}

func TestRead(t *testing.T) {
	const bufferSize = 20

	tempDir := t.TempDir()
	os.WriteFile(path.Join(tempDir, "bar"), []byte("bar"), 0600)

	os.WriteFile(path.Join(tempDir, "baz"), []byte("baz"), 0600)
	openedRootFile, err := os.OpenFile(path.Join(tempDir, "baz"), os.O_RDONLY, filePermission)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	// Close the file after the test. The file should be closed via the fileNode.Close method,
	// however, this test explicitly closes the file since the fileNode.Close method is tested in a
	// separate test.
	defer openedRootFile.Close()

	os.MkdirAll(path.Join(tempDir, "dir1"), 0700)
	os.WriteFile(path.Join(tempDir, "dir1/foo"), []byte("foo"), 0600)

	fileNodeWithUnopenedFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/bar",
		isWhiteout:    false,
		mode:          filePermission,
	}
	fileNodeWithOpenedFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/baz",
		isWhiteout:    false,
		mode:          filePermission,
		file:          openedRootFile,
	}
	fileNodeNonRootFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/dir1/foo",
		isWhiteout:    false,
		mode:          filePermission,
	}
	fileNodeNonExistentFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/dir1/xyz",
		isWhiteout:    false,
		mode:          filePermission,
	}
	fileNodeWhiteoutFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/dir1/abc",
		isWhiteout:    true,
		mode:          filePermission,
	}
	tests := []struct {
		name    string
		node    *fileNode
		want    string
		wantErr bool
	}{
		{
			name: "unopened root file",
			node: fileNodeWithUnopenedFile,
			want: "bar",
		},
		{
			name: "opened root file",
			node: fileNodeWithOpenedFile,
			want: "baz",
		},
		{
			name: "non-root file",
			node: fileNodeNonRootFile,
			want: "foo",
		},
		{
			name:    "non-existent file",
			node:    fileNodeNonExistentFile,
			wantErr: true,
		},
		{
			name:    "whiteout file",
			node:    fileNodeWhiteoutFile,
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
			tc.node.Close()
		})
	}
}

func TestClose(t *testing.T) {
	const bufferSize = 20

	tempDir := t.TempDir()
	os.WriteFile(path.Join(tempDir, "bar"), []byte("bar"), 0600)

	fileNodeWithUnopenedFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/bar",
		isWhiteout:    false,
		mode:          filePermission,
	}
	fileNodeNonExistentFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/dir1/xyz",
		isWhiteout:    false,
		mode:          filePermission,
	}

	tests := []struct {
		name string
		node *fileNode
	}{
		{
			name: "unopened root file",
			node: fileNodeWithUnopenedFile,
		},
		{
			name: "non-existent file",
			node: fileNodeNonExistentFile,
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
	os.WriteFile(path.Join(tempDir, "bar"), []byte("bar"), 0600)
	os.WriteFile(path.Join(tempDir, "baz"), []byte("baz"), 0600)
	openedRootFile, err := os.OpenFile(path.Join(tempDir, "baz"), os.O_RDONLY, filePermission)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}

	fileNodeWithUnopenedFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/bar",
		isWhiteout:    false,
		mode:          filePermission,
	}
	fileNodeWithOpenedFile := &fileNode{
		extractDir:    tempDir,
		originLayerID: "",
		virtualPath:   "/baz",
		isWhiteout:    false,
		mode:          filePermission,
		file:          openedRootFile,
	}

	tests := []struct {
		name    string
		node    *fileNode
		want    string
		wantErr bool
	}{
		{
			name: "unopened root file",
			node: fileNodeWithUnopenedFile,
			want: "bar",
		},
		{
			name: "opened root file",
			node: fileNodeWithOpenedFile,
			want: "baz",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < readAndCloseEvents; i++ {
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
		node *fileNode
		want string
	}{
		{
			name: "root directory",
			node: rootDirectory,
			want: "/tmp/extract/layer1",
		},
		{
			name: "root file",
			node: rootFile,
			want: "/tmp/extract/layer1/bar",
		},
		{
			name: "non-root file",
			node: nonRootFile,
			want: "/tmp/extract/layer1/dir1/foo",
		},
		{
			name: "non-root directory",
			node: nonRootDirectory,
			want: "/tmp/extract/layer1/dir1/dir2",
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
		node *fileNode
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
		node *fileNode
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
		node *fileNode
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
