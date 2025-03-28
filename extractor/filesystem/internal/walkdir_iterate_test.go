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

// These are the same tests as in io/fs/walk_test.go, but ignoring the order of walking.
package internal

import (
	"errors"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"testing/fstest"
	"time"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

type Node struct {
	name    string
	entries []*Node // nil if the entry is a file
	mark    int
}

var tree = &Node{
	"testdata",
	[]*Node{
		{"a", nil, 0},
		{"b", []*Node{}, 0},
		{"c", nil, 0},
		{
			"d",
			[]*Node{
				{"x", nil, 0},
				{"y", []*Node{}, 0},
				{
					"z",
					[]*Node{
						{"u", nil, 0},
						{"v", nil, 0},
					},
					0,
				},
			},
			0,
		},
	},
	0,
}

func walkTree(n *Node, path string, f func(path string, n *Node)) {
	f(path, n)
	for _, e := range n.entries {
		walkTree(e, pathpkg.Join(path, e.name), f)
	}
}

func makeTree() scalibrfs.FS {
	fsys := fstest.MapFS{}
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.entries == nil {
			fsys[path] = &fstest.MapFile{}
		} else {
			fsys[path] = &fstest.MapFile{Mode: fs.ModeDir}
		}
	})
	return fsys
}

// Assumes that each node name is unique. Good enough for a test.
// If clearErr is true, any incoming error is cleared before return. The errors
// are always accumulated, though.
func mark(tree *Node, entry fs.DirEntry, err error, errors *[]error, clearErr bool) error {
	name := entry.Name()
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.name == name {
			n.mark++
		}
	})
	if err != nil {
		*errors = append(*errors, err)
		if clearErr {
			return nil
		}
		return err
	}
	return nil
}

func TestWalkDir(t *testing.T) {
	tmpDir := t.TempDir()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal("finding working dir:", err)
	}
	if err = os.Chdir(tmpDir); err != nil {
		t.Fatal("entering temp dir:", err)
	}
	//nolint:errcheck
	defer os.Chdir(origDir)

	fsys := makeTree()
	errors := make([]error, 0, 10)
	clearErr := true
	markFn := func(path string, entry fs.DirEntry, err error) error {
		return mark(tree, entry, err, &errors, clearErr)
	}
	// Expect no errors.
	err = WalkDirUnsorted(fsys, ".", markFn, nil)
	if err != nil {
		t.Fatalf("no error expected, found: %s", err)
	}
	if len(errors) != 0 {
		t.Fatalf("unexpected errors: %s", errors)
	}
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.mark != 1 {
			t.Errorf("node %s mark = %d; expected 1", path, n.mark)
		}
		n.mark = 0
	})
}

func TestIssue51617(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"a", filepath.Join("a", "bad"), filepath.Join("a", "next")} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	bad := filepath.Join(dir, "a", "bad")
	if err := os.Chmod(bad, 0); err != nil {
		t.Fatal(err)
	}
	//nolint:errcheck
	defer os.Chmod(bad, 0700) // avoid errors on cleanup
	var saw []string
	err := WalkDirUnsorted(scalibrfs.DirFS(dir), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if d.IsDir() {
			saw = append(saw, path)
		}
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".", "a", "a/bad", "a/next"}
	sort.Strings(saw)
	if !reflect.DeepEqual(saw, want) {
		t.Errorf("got directories %v, want %v", saw, want)
	}
}

// FS implementation that doesn't implement ReadDirFile on the sub-directories.
type fakeFS struct{}

func (f fakeFS) Open(name string) (fs.File, error) {
	return &fakeFile{}, nil
}
func (fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "." { // root dir
		return []fs.DirEntry{
			&fakeDirEntry{name: "file1.txt", isDir: false},
			&fakeDirEntry{name: "dir", isDir: true},
		}, nil
	} else if name == "dir" {
		return []fs.DirEntry{&fakeDirEntry{name: "file2.txt", isDir: false}}, nil
	}
	return nil, errors.New("file not found")
}
func (fakeFS) Stat(name string) (fs.FileInfo, error) {
	return &fakeDirEntry{name: name, isDir: name == "." || name == "dir"}, nil
}

type fakeFile struct{}

func (f *fakeFile) Stat() (fs.FileInfo, error)                { return nil, nil }
func (f *fakeFile) Read(buffer []byte) (count int, err error) { return 0, io.EOF }
func (*fakeFile) Close() error                                { return nil }

var fakeFSTree = &Node{
	".",
	[]*Node{
		{"file1.txt", nil, 0},
		{
			"dir",
			[]*Node{{"file2.txt", nil, 0}},
			0,
		},
	},
	0,
}

type fakeDirEntry struct {
	name  string
	isDir bool
}

func (f *fakeDirEntry) Name() string               { return f.name }
func (f *fakeDirEntry) Size() int64                { return 0 }
func (f *fakeDirEntry) Mode() fs.FileMode          { return 0 }
func (f *fakeDirEntry) ModTime() time.Time         { return time.Time{} }
func (f *fakeDirEntry) IsDir() bool                { return f.isDir }
func (f *fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f *fakeDirEntry) Info() (fs.FileInfo, error) { return nil, errors.New("not implemented") }
func (f *fakeDirEntry) Sys() any                   { return nil }

func TestWalkDirFallbackToDirFS(t *testing.T) {
	fsys := &fakeFS{}
	errors := make([]error, 0, 10)
	clearErr := true
	markFn := func(path string, entry fs.DirEntry, err error) error {
		return mark(fakeFSTree, entry, err, &errors, clearErr)
	}
	// Expect no errors.
	if err := WalkDirUnsorted(fsys, ".", markFn, nil); err != nil {
		t.Fatalf("no error expected, found: %s", err)
	}
	if len(errors) != 0 {
		t.Fatalf("unexpected errors: %s", errors)
	}
	walkTree(fakeFSTree, fakeFSTree.name, func(path string, n *Node) {
		if n.mark != 1 {
			t.Errorf("node %s mark = %d; expected 1", path, n.mark)
		}
		n.mark = 0
	})
}
