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
	"path"
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

func testTree(t *testing.T) *Node {
	t.Helper()

	tree := NewNode()
	assertNoError(t, tree.Insert("/", &virtualFile{virtualPath: "/", layerDir: "/layer0", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a", &virtualFile{virtualPath: "/a", layerDir: "/layer1", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/b", &virtualFile{virtualPath: "/a/b", layerDir: "/layer1", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/b/c", &virtualFile{virtualPath: "/a/b/c", layerDir: "/layer1", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/b/d", &virtualFile{virtualPath: "/a/b/d", layerDir: "/layer1", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/b/d/f", &virtualFile{virtualPath: "/a/b/d/f", layerDir: "/layer1", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/e", &virtualFile{virtualPath: "/a/e", layerDir: "/layer2", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/e/f", &virtualFile{virtualPath: "/a/e/f", layerDir: "/layer2", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/a/g", &virtualFile{virtualPath: "a/g", layerDir: "/layer3", mode: fs.ModeDir}))
	assertNoError(t, tree.Insert("/x/y/z", &virtualFile{virtualPath: "/x/y/z", layerDir: "/layer4", mode: fs.ModeDir}))

	return tree
}

func TestNode_Insert_Error(t *testing.T) {
	tests := []struct {
		name string
		tree *Node
		key  string
		val  *virtualFile
	}{
		{
			name: "duplicate node",
			tree: func() *Node {
				tree := NewNode()
				_ = tree.Insert("/a", &virtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			key: "/a",
			val: &virtualFile{virtualPath: "/a", mode: fs.ModeDir},
		},
		{
			name: "duplicate node in subtree",
			tree: func() *Node {
				tree := NewNode()
				_ = tree.Insert("/a", &virtualFile{virtualPath: "/a", mode: fs.ModeDir})
				_ = tree.Insert("/a/b", &virtualFile{virtualPath: "/a/b", mode: fs.ModeDir})

				return tree
			}(),
			key: "/a/b",
			val: &virtualFile{virtualPath: "/a/b", mode: fs.ModeDir},
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
		name string
		tree *Node
		key  string
		want *virtualFile
	}{
		{
			name: "empty tree",
			tree: NewNode(),
			key:  "/a",
			want: nil,
		},
		{
			name: "single node",
			tree: func() *Node {
				tree := NewNode()
				_ = tree.Insert("/a", &virtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			key:  "/a",
			want: &virtualFile{virtualPath: "/a", mode: fs.ModeDir},
		},
		{
			name: "nonexistent node in single node tree",
			tree: func() *Node {
				tree := NewNode()
				_ = tree.Insert("/a", &virtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			key:  "/b",
			want: nil,
		},
		{
			name: "root node",
			tree: testTree(t),
			key:  "/",
			want: &virtualFile{virtualPath: "/", layerDir: "/layer0", mode: fs.ModeDir},
		},
		{
			name: "multiple nodes",
			tree: testTree(t),
			key:  "/a/b/c",
			want: &virtualFile{virtualPath: "/a/b/c", layerDir: "/layer1", mode: fs.ModeDir},
		},
		{
			name: "nonexistent node",
			tree: testTree(t),
			key:  "/a/b/g",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tree.Get(tt.key)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(virtualFile{})); diff != "" {
				t.Errorf("Node.Get() (-want +got): %v", diff)
			}
		})
	}
}

func TestNode_GetChildren(t *testing.T) {
	tests := []struct {
		name string
		tree *Node
		key  string
		want []*virtualFile
	}{
		{
			name: "empty tree",
			tree: NewNode(),
			key:  "/a",
			want: nil,
		},
		{
			name: "single node no children",
			tree: func() *Node {
				tree := NewNode()
				_ = tree.Insert("/a", &virtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			key:  "/a",
			want: []*virtualFile{},
		},
		{
			name: "root node",
			tree: testTree(t),
			key:  "/",
			// /x is not included since value is nil.
			want: []*virtualFile{
				{virtualPath: "/a", layerDir: "/layer1", mode: fs.ModeDir},
			},
		},
		{
			name: "multiple nodes with children",
			tree: testTree(t),
			key:  "/a/b",
			want: []*virtualFile{
				{virtualPath: "/a/b/c", layerDir: "/layer1", mode: fs.ModeDir},
				{virtualPath: "/a/b/d", layerDir: "/layer1", mode: fs.ModeDir},
			},
		},
		{
			name: "nonexistent node",
			tree: testTree(t),
			key:  "/a/b/g",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tree.GetChildren(tt.key)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(virtualFile{}), cmpopts.SortSlices(func(a, b *virtualFile) bool {
				return strings.Compare(a.RealFilePath(), b.RealFilePath()) < 0
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
		tree *Node
		want []keyValue
	}{
		{
			name: "empty tree",
			tree: NewNode(),
			want: []keyValue{},
		},
		{
			name: "single node",
			tree: func() *Node {
				tree := NewNode()
				_ = tree.Insert("/a", &virtualFile{virtualPath: "/a", mode: fs.ModeDir})

				return tree
			}(),
			want: []keyValue{
				{"/a", "/a"},
			},
		},
		{
			name: "multiple nodes",
			tree: testTree(t),
			want: []keyValue{
				{key: "", val: "/layer0"},
				{key: "/a", val: "/layer1/a"},
				{key: "/a/b", val: "/layer1/a/b"},
				{key: "/a/b/c", val: "/layer1/a/b/c"},
				{key: "/a/b/d", val: "/layer1/a/b/d"},
				{key: "/a/b/d/f", val: "/layer1/a/b/d/f"},
				{key: "/a/e", val: "/layer2/a/e"},
				{key: "/a/e/f", val: "/layer2/a/e/f"},
				{key: "/a/g", val: "/layer3/a/g"},
				{key: "/x/y/z", val: "/layer4/x/y/z"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := []keyValue{}
			err := tt.tree.Walk(func(p string, vf *virtualFile) error {
				got = append(got, keyValue{key: p, val: path.Join(vf.layerDir, vf.virtualPath)})
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
