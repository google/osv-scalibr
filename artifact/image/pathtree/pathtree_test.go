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

package pathtree

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type testVal struct {
	string
}

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Errorf("%v", err)
	}
}

func testTree(t *testing.T) *Node[testVal] {
	t.Helper()

	tree := NewNode[testVal]()
	assertNoError(t, tree.Insert("/", &testVal{"value0"}))
	assertNoError(t, tree.Insert("/a", &testVal{"value1"}))
	assertNoError(t, tree.Insert("/a/b", &testVal{"value2"}))
	assertNoError(t, tree.Insert("/a/b/c", &testVal{"value3"}))
	assertNoError(t, tree.Insert("/a/b/d", &testVal{"value4"}))
	assertNoError(t, tree.Insert("/a/e", &testVal{"value5"}))
	assertNoError(t, tree.Insert("/a/e/f", &testVal{"value6"}))
	assertNoError(t, tree.Insert("/a/b/d/f", &testVal{"value7"}))
	assertNoError(t, tree.Insert("/a/g", &testVal{"value8"}))
	assertNoError(t, tree.Insert("/x/y/z", &testVal{"value9"}))

	return tree
}

func TestNode_Insert_Error(t *testing.T) {
	tests := []struct {
		name string
		tree *Node[testVal]
		key  string
		val  *testVal
	}{
		{
			name: "duplicate node",
			tree: func() *Node[testVal] {
				tree := NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value1"})

				return tree
			}(),
			key: "/a",
			val: &testVal{"value2"},
		},
		{
			name: "duplicate node in subtree",
			tree: func() *Node[testVal] {
				tree := NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value1"})
				_ = tree.Insert("/a/b", &testVal{"value2"})

				return tree
			}(),
			key: "/a/b",
			val: &testVal{"value3"},
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
		tree *Node[testVal]
		key  string
		want *testVal
	}{
		{
			name: "empty tree",
			tree: NewNode[testVal](),
			key:  "/a",
			want: nil,
		},
		{
			name: "single node",
			tree: func() *Node[testVal] {
				tree := NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value"})

				return tree
			}(),
			key:  "/a",
			want: &testVal{"value"},
		},
		{
			name: "nonexistent node in single node tree",
			tree: func() *Node[testVal] {
				tree := NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value"})

				return tree
			}(),
			key:  "/b",
			want: nil,
		},
		{
			name: "root node",
			tree: testTree(t),
			key:  "/",
			want: &testVal{"value0"},
		},
		{
			name: "multiple nodes",
			tree: testTree(t),
			key:  "/a/b/c",
			want: &testVal{"value3"},
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
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(testVal{})); diff != "" {
				t.Errorf("Node.Get() (-want +got): %v", diff)
			}
		})
	}
}

func TestNode_GetChildren(t *testing.T) {
	tests := []struct {
		name string
		tree *Node[testVal]
		key  string
		want []*testVal
	}{
		{
			name: "empty tree",
			tree: NewNode[testVal](),
			key:  "/a",
			want: nil,
		},
		{
			name: "single node no children",
			tree: func() *Node[testVal] {
				tree := NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value"})

				return tree
			}(),
			key:  "/a",
			want: []*testVal{},
		},
		{
			name: "root node",
			tree: testTree(t),
			key:  "/",
			// /x is not included since the subdir is nil.
			want: []*testVal{
				{"value1"}, // "value1" is a value of /a
			},
		},
		{
			name: "multiple nodes with children",
			tree: testTree(t),
			key:  "/a/b",
			want: []*testVal{
				{"value3"},
				{"value4"},
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
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(testVal{}), cmpopts.SortSlices(func(a, b *testVal) bool {
				return strings.Compare(a.string, b.string) < 0
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
		tree *Node[testVal]
		want []keyValue
	}{
		{
			name: "empty tree",
			tree: NewNode[testVal](),
			want: []keyValue{},
		},
		{
			name: "single node",
			tree: func() *Node[testVal] {
				tree := NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value"})

				return tree
			}(),
			want: []keyValue{
				{"/a", "value"},
			},
		},
		{
			name: "multiple nodes",
			tree: testTree(t),
			want: []keyValue{
				{key: "", val: "value0"},
				{key: "/a", val: "value1"},
				{key: "/a/b", val: "value2"},
				{key: "/a/b/c", val: "value3"},
				{key: "/a/b/d", val: "value4"},
				{key: "/a/e", val: "value5"},
				{key: "/a/e/f", val: "value6"},
				{key: "/a/b/d/f", val: "value7"},
				{key: "/a/g", val: "value8"},
				{key: "/x/y/z", val: "value9"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := []keyValue{}
			err := tt.tree.Walk(func(path string, node *testVal) error {
				got = append(got, keyValue{key: path, val: node.string})
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
