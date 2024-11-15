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

// TODO: b/377551664 - Add tests for the Stat, Read, and Close methods for the fileNode type.
func TestStat(t *testing.T) {
	return
}

func TestRead(t *testing.T) {
	return
}

func TestClose(t *testing.T) {
	return
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
