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
	"io/fs"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Errorf("%v", err)
	}
}

func testTree(t *testing.T) *RootNode {
	t.Helper()

	tree := NewNode(DefaultMaxSymlinkDepth)
	assertNoError(t, tree.Insert("/", &VirtualFile{virtualPath: "/", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a", &VirtualFile{virtualPath: "/a", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/b", &VirtualFile{virtualPath: "/a/b", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/b/c", &VirtualFile{virtualPath: "/a/b/c", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/b/d", &VirtualFile{virtualPath: "/a/b/d", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/b/d/f", &VirtualFile{virtualPath: "/a/b/d/f", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/e", &VirtualFile{virtualPath: "/a/e", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/e/f", &VirtualFile{virtualPath: "/a/e/f", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/g", &VirtualFile{virtualPath: "/a/g", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/x/y/z", &VirtualFile{virtualPath: "/x/y/z", mode: fs.ModeDir}))

	return tree
}

func TestNode_Insert_Error(t *testing.T) {
	tests := []struct {
		name string
		tree *RootNode
		key  string
		val  *VirtualFile
	}{
		{
			name: "duplicate node",
			tree: func() *RootNode {
				tree := NewNode(DefaultMaxSymlinkDepth)
				_ = tree.Insert("/a", &VirtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			key: "/a",
			val: &VirtualFile{virtualPath: "/a", mode: fs.ModeDir},
		},
		{
			name: "duplicate node in subtree",
			tree: func() *RootNode {
				tree := NewNode(DefaultMaxSymlinkDepth)
				_ = tree.Insert("/a", &VirtualFile{virtualPath: "/a", mode: fs.ModeDir})
				_ = tree.Insert("/a/b", &VirtualFile{virtualPath: "/a/b", mode: fs.ModeDir})

				return tree
			}(),
			key: "/a/b",
			val: &VirtualFile{virtualPath: "/a/b", mode: fs.ModeDir},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tree.Insert(tt.key, tt.val)
			if err == nil {
				t.Errorf("Node.Insert() expected error, got nil")
			}
		})
	}
}

func TestNode_Get(t *testing.T) {
	tests := []struct {
		name    string
		tree    *RootNode
		key     string
		want    *VirtualFile
		wantErr error
	}{
		{
			name:    "empty tree",
			tree:    NewNode(DefaultMaxSymlinkDepth),
			key:     "/a",
			want:    nil,
			wantErr: fs.ErrNotExist,
		},
		{
			name: "single node",
			tree: func() *RootNode {
				tree := NewNode(DefaultMaxSymlinkDepth)
				_ = tree.Insert("/a", &VirtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			key:  "/a",
			want: &VirtualFile{virtualPath: "/a", mode: fs.ModeDir},
		},
		{
			name: "nonexistent node in single node tree",
			tree: func() *RootNode {
				tree := NewNode(DefaultMaxSymlinkDepth)
				_ = tree.Insert("/a", &VirtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			key:     "/b",
			want:    nil,
			wantErr: fs.ErrNotExist,
		},
		{
			name: "root node",
			tree: testTree(t),
			key:  "/",
			want: &VirtualFile{virtualPath: "/", mode: fs.ModeDir},
		},
		{
			name: "multiple nodes",
			tree: testTree(t),
			key:  "/a/b/c",
			want: &VirtualFile{virtualPath: "/a/b/c", mode: fs.ModeDir},
		},
		{
			name:    "nonexistent node",
			tree:    testTree(t),
			key:     "/a/b/g",
			want:    nil,
			wantErr: fs.ErrNotExist,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tree.Get(tt.key, true)
			if errDiff := cmp.Diff(err, tt.wantErr, cmpopts.EquateErrors()); errDiff != "" {
				t.Errorf("Node.Get() err diff (-want +got):\n%s", errDiff)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(VirtualFile{})); diff != "" {
				t.Errorf("Node.Get() (-want +got): %v", diff)
			}
		})
	}
}

func TestNode_GetChildren(t *testing.T) {
	tests := []struct {
		name    string
		tree    *RootNode
		key     string
		want    []*VirtualFile
		wantErr error
	}{
		{
			name:    "empty tree",
			tree:    NewNode(DefaultMaxSymlinkDepth),
			key:     "/a",
			want:    nil,
			wantErr: fs.ErrNotExist,
		},
		{
			name: "single node no children",
			tree: func() *RootNode {
				tree := NewNode(DefaultMaxSymlinkDepth)
				_ = tree.Insert("/a", &VirtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			key:  "/a",
			want: []*VirtualFile{},
		},
		{
			name: "root node",
			tree: testTree(t),
			key:  "/",
			// /x is not included since value is nil.
			want: []*VirtualFile{
				{virtualPath: "/a", mode: fs.ModeDir},
			},
		},
		{
			name: "multiple nodes with children",
			tree: testTree(t),
			key:  "/a/b",
			want: []*VirtualFile{
				{virtualPath: "/a/b/c", mode: fs.ModeDir},
				{virtualPath: "/a/b/d", mode: fs.ModeDir},
			},
		},
		{
			name:    "nonexistent node",
			tree:    testTree(t),
			key:     "/a/b/g",
			want:    nil,
			wantErr: fs.ErrNotExist,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tree.GetChildren(tt.key)
			if errDiff := cmp.Diff(err, tt.wantErr, cmpopts.EquateErrors()); errDiff != "" {
				t.Errorf("Node.Get() err diff (-want +got):\n%s", errDiff)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(VirtualFile{}), cmpopts.SortSlices(func(a, b *VirtualFile) bool {
				return strings.Compare(a.virtualPath, b.virtualPath) < 0
			})); diff != "" {
				t.Errorf("Node.GetChildren() (-want +got): %v", diff)
			}
		})
	}
}

type keyValue struct {
	key string
	val string
}

func TestNode_Walk(t *testing.T) {
	tests := []struct {
		name string
		tree *RootNode
		want []keyValue
	}{
		{
			name: "empty tree",
			tree: NewNode(DefaultMaxSymlinkDepth),
			want: []keyValue{
				{"", "/"},
			},
		},
		{
			name: "single node",
			tree: func() *RootNode {
				tree := NewNode(DefaultMaxSymlinkDepth)
				_ = tree.Insert("/a", &VirtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			want: []keyValue{
				{"", "/"},
				{"/a", "/a"},
			},
		},
		{
			name: "multiple nodes",
			tree: testTree(t),
			want: []keyValue{
				{key: "", val: "/"},
				{key: "/a", val: "/a"},
				{key: "/a/b", val: "/a/b"},
				{key: "/a/b/c", val: "/a/b/c"},
				{key: "/a/b/d", val: "/a/b/d"},
				{key: "/a/b/d/f", val: "/a/b/d/f"},
				{key: "/a/e", val: "/a/e"},
				{key: "/a/e/f", val: "/a/e/f"},
				{key: "/a/g", val: "/a/g"},
				{key: "/x/y/z", val: "/x/y/z"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := []keyValue{}
			err := tt.tree.Walk(func(p string, vf *VirtualFile) error {
				got = append(got, keyValue{key: p, val: vf.virtualPath})
				return nil
			})
			if err != nil {
				t.Errorf("Node.Walk() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(keyValue{}), cmpopts.SortSlices(func(a, b keyValue) bool {
				if a.key == b.key {
					return a.val < b.val
				}
				return a.key < b.key
			})); diff != "" {
				t.Errorf("Node.Walk() (-want +got): %v", diff)
			}
		})
	}
}
