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

package internal

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/testing/fakefs"
)

// These are the same tests as in io/fs/walk_test.go, but ignoring the order of walking.

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
	t.Chdir(t.TempDir())

	fsys := makeTree()
	errors := make([]error, 0, 10)
	clearErr := true
	markFn := func(path string, entry fs.DirEntry, err error) error {
		return mark(tree, entry, err, &errors, clearErr)
	}
	// Expect no errors.
	err := WalkDirUnsorted(fsys, ".", markFn, nil)
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
	err := WalkDirUnsorted(fakefs.DirFS(t, dir), ".", func(path string, d fs.DirEntry, err error) error {
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
	slices.Sort(saw)
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

func TestWalkDirUnsorted_RealFS(t *testing.T) {
	t.Run("deep_tree_past_subroot_cap_and_postfn_order", func(t *testing.T) {
		root := t.TempDir()
		const depth = 40
		parts := make([]string, 0, depth)
		for i := range depth {
			parts = append(parts, fmt.Sprintf("d%02d", i))
		}
		deepDir := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(deepDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(deepDir, "leaf.txt"), []byte("deep-leaf"), 0o644); err != nil {
			t.Fatal(err)
		}

		fsys := fakefs.DirFS(t, root)

		wantLeaf := strings.Join(parts, "/") + "/leaf.txt"
		var sawLeaf bool
		visitedDirs := 0
		closedDirs := make(map[string]bool)
		err := WalkDirUnsorted(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Parent directory must not have completed postFN before its children are visited.
			if p != "." {
				parent := pathpkg.Dir(p)
				if closedDirs[parent] {
					t.Errorf("postFN ran for parent %q before child %q was visited", parent, p)
				}
			}
			if d.IsDir() {
				visitedDirs++
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				t.Errorf("d.Info() for %q: %v", p, infoErr)
				return nil
			}
			if p == wantLeaf {
				sawLeaf = true
				if info.Size() != int64(len("deep-leaf")) {
					t.Errorf("leaf size = %d, want %d", info.Size(), len("deep-leaf"))
				}
			}
			return nil
		}, func(p string, d fs.DirEntry) {
			if d != nil && d.IsDir() {
				closedDirs[p] = true
			}
		})
		if err != nil {
			t.Fatalf("WalkDirUnsorted: %v", err)
		}
		if !sawLeaf {
			t.Errorf("did not visit deep leaf %q", wantLeaf)
		}
		if visitedDirs != depth+1 {
			t.Errorf("visitedDirs = %d, want %d", visitedDirs, depth+1)
		}
		if !closedDirs["."] || !closedDirs[strings.Join(parts, "/")] {
			t.Errorf("postFN missed root or deepest directory: closed count = %d", len(closedDirs))
		}
	})

	t.Run("skip_dir_and_skip_all", func(t *testing.T) {
		root := t.TempDir()
		for _, p := range []string{"keep/a.txt", "skip/b.txt", "skip/nested/c.txt"} {
			full := filepath.Join(root, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		fsys := fakefs.DirFS(t, root)

		var files []string
		err := WalkDirUnsorted(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == "skip" {
				return fs.SkipDir
			}
			if !d.IsDir() {
				files = append(files, p)
			}
			return nil
		}, nil)
		if err != nil {
			t.Fatalf("WalkDirUnsorted(SkipDir): %v", err)
		}
		if want := []string{"keep/a.txt"}; !slices.Equal(files, want) {
			t.Errorf("files after SkipDir = %v, want %v", files, want)
		}

		calls := 0
		err = WalkDirUnsorted(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			calls++
			if calls == 2 {
				return fs.SkipAll
			}
			return nil
		}, nil)
		if err != nil {
			t.Fatalf("WalkDirUnsorted(SkipAll): %v", err)
		}
		if calls != 2 {
			t.Errorf("SkipAll callback count = %d, want 2", calls)
		}
	})

	t.Run("symlinks_and_confinement", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation may require elevated privileges on Windows")
		}
		parent := t.TempDir()
		outsideDir := filepath.Join(parent, "outside")
		if err := os.MkdirAll(outsideDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("host-secret"), 0o600); err != nil {
			t.Fatal(err)
		}

		root := filepath.Join(parent, "rootfs")
		if err := os.MkdirAll(filepath.Join(root, "realdir"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "realdir", "inside.txt"), []byte("ok"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("realdir", filepath.Join(root, "dirlink")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideDir, filepath.Join(root, "escape")); err != nil {
			t.Fatal(err)
		}

		fsys := fakefs.DirFS(t, root)

		// Walking "." must not descend into symlinked child directories or escaping symlinks.
		var visited []string
		err := WalkDirUnsorted(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			visited = append(visited, p)
			if p == "dirlink" || p == "escape" {
				if d.IsDir() || d.Type()&fs.ModeSymlink == 0 {
					t.Errorf("%q IsDir=%v Type=%v, want non-dir symlink", p, d.IsDir(), d.Type())
				}
			}
			return nil
		}, nil)
		if err != nil {
			t.Fatalf("WalkDirUnsorted(.): %v", err)
		}
		slices.Sort(visited)
		want := []string{".", "dirlink", "escape", "realdir", "realdir/inside.txt"}
		if !slices.Equal(visited, want) {
			t.Errorf("visited = %v, want %v", visited, want)
		}

		// Walking a symlinked root itself must follow the root symlink.
		var rootLinkVisited []string
		err = WalkDirUnsorted(fsys, "dirlink", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rootLinkVisited = append(rootLinkVisited, p)
			return nil
		}, nil)
		if err != nil {
			t.Fatalf("WalkDirUnsorted(dirlink): %v", err)
		}
		slices.Sort(rootLinkVisited)
		if wantRoot := []string{"dirlink", "dirlink/inside.txt"}; !slices.Equal(rootLinkVisited, wantRoot) {
			t.Errorf("WalkDirUnsorted(dirlink) = %v, want %v", rootLinkVisited, wantRoot)
		}
	})

	t.Run("permission_denied_preserves_full_path", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("chmod 0 does not deny directory reads on Windows or as root")
		}
		root := t.TempDir()
		for _, sub := range []string{"a", filepath.Join("a", "bad"), filepath.Join("a", "next")} {
			if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, "a", "next", "ok.txt"), []byte("ok"), 0o644); err != nil {
			t.Fatal(err)
		}
		bad := filepath.Join(root, "a", "bad")
		if err := os.Chmod(bad, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(bad, 0o700) })

		fsys := fakefs.DirFS(t, root)

		var errPaths []string
		var sawNextFile bool
		err := WalkDirUnsorted(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				errPaths = append(errPaths, p)
				var pe *fs.PathError
				if !errors.As(err, &pe) || pe.Path != p {
					t.Errorf("error for %q has PathError %v, want Path == %q", p, pe, p)
				}
				return fs.SkipDir
			}
			if p == "a/next/ok.txt" {
				sawNextFile = true
			}
			return nil
		}, nil)
		if err != nil {
			t.Fatalf("WalkDirUnsorted: %v", err)
		}
		if want := []string{"a/bad"}; !slices.Equal(errPaths, want) {
			t.Errorf("error paths = %v, want %v", errPaths, want)
		}
		if !sawNextFile {
			t.Error("expected walk to continue visiting sibling a/next/ok.txt")
		}
	})
}

func TestNormalizePathError(t *testing.T) {
	sentinel := errors.New("boom")
	samePE := &fs.PathError{Op: "open", Path: "a/b", Err: sentinel}
	wrapped := fmt.Errorf("context: %w", &fs.PathError{Op: "open", Path: "b", Err: sentinel})

	if got := NormalizePathError(nil, "a/b"); got != nil {
		t.Errorf("NormalizePathError(nil) = %v, want nil", got)
	}
	if got := NormalizePathError(sentinel, "a/b"); !errors.Is(got, sentinel) {
		t.Errorf("NormalizePathError(non-PathError) = %v, want %v", got, sentinel)
	}
	if got := NormalizePathError(samePE, "a/b"); reflect.ValueOf(got).Pointer() != reflect.ValueOf(samePE).Pointer() {
		t.Errorf("NormalizePathError(same path) reallocated: got %p, want %p", got, samePE)
	}
	if got := NormalizePathError(wrapped, "a/b"); !errors.Is(got, wrapped) || got.Error() != wrapped.Error() {
		t.Errorf("NormalizePathError(wrapped) = %v, want original wrapped error preserved", got)
	}

	subPE := &fs.PathError{Op: "lstat", Path: "b", Err: sentinel}
	got := NormalizePathError(subPE, "a/b")
	var pe *fs.PathError
	if !errors.As(got, &pe) || pe.Op != "lstat" || pe.Path != "a/b" || !errors.Is(pe.Err, sentinel) {
		t.Errorf("NormalizePathError(sub-root PathError) = %#v, want Op=lstat Path=a/b Err=%v", got, sentinel)
	}
}

type failingReadDirFile struct {
	err error
}

func (f *failingReadDirFile) Stat() (fs.FileInfo, error) { return nil, nil }
func (f *failingReadDirFile) Read([]byte) (int, error)   { return 0, io.EOF }
func (f *failingReadDirFile) Close() error               { return nil }
func (f *failingReadDirFile) ReadDir(int) ([]fs.DirEntry, error) {
	return nil, &fs.PathError{Op: "readdirent", Path: ".", Err: f.err}
}

type failingSubFS struct {
	err      error
	nextFile *failingReadDirFile
	closed   bool
}

func newFailingSubFS(readDirErr, nextErr error) *failingSubFS {
	var nextFile *failingReadDirFile
	if nextErr != nil {
		nextFile = &failingReadDirFile{err: nextErr}
	}
	return &failingSubFS{err: readDirErr, nextFile: nextFile}
}

func (f *failingSubFS) Open(name string) (fs.File, error) {
	if f.nextFile != nil {
		return f.nextFile, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: f.err}
}

func (f *failingSubFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, &fs.PathError{Op: "readdir", Path: name, Err: f.err}
}

func (f *failingSubFS) Stat(name string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "stat", Path: name, Err: f.err}
}

func (f *failingSubFS) Close() error {
	f.closed = true
	return nil
}

type emfileFallbackFS struct {
	base             fstest.MapFS
	openSubFSErr     error
	failSubTarget    string
	subFSReadDirErr  error
	subFSNextErr     error
	parentReadDirErr error
	openedSubs       []*failingSubFS
}

func (f *emfileFallbackFS) Open(name string) (fs.File, error) {
	if f.parentReadDirErr != nil && name == f.failSubTarget {
		return nil, &fs.PathError{Op: "open", Path: name, Err: f.parentReadDirErr}
	}
	return f.base.Open(name)
}

func (f *emfileFallbackFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if f.parentReadDirErr != nil && name == f.failSubTarget {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: f.parentReadDirErr}
	}
	return f.base.ReadDir(name)
}

func (f *emfileFallbackFS) Stat(name string) (fs.FileInfo, error) {
	return f.base.Stat(name)
}

func (f *emfileFallbackFS) OpenSubFS(name string) (scalibrfs.FS, error) {
	if f.failSubTarget != "" && name != f.failSubTarget {
		return nil, &fs.PathError{Op: "opensubfs", Path: name, Err: errors.ErrUnsupported}
	}
	if f.openSubFSErr != nil {
		return nil, &fs.PathError{Op: "opensubfs", Path: name, Err: f.openSubFSErr}
	}
	sub := newFailingSubFS(f.subFSReadDirErr, f.subFSNextErr)
	f.openedSubs = append(f.openedSubs, sub)
	return sub, nil
}

func TestWalkDirUnsorted_EMFILEFallback(t *testing.T) {
	base := fstest.MapFS{
		"a/b/leaf.txt":  &fstest.MapFile{Data: []byte("leaf")},
		"a/ok/keep.txt": &fstest.MapFile{Data: []byte("keep")},
	}

	tests := []struct {
		name             string
		openSubFSErr     error
		failSubTarget    string
		subFSReadDirErr  error
		subFSNextErr     error
		parentReadDirErr error
		wantFiles        []string
		wantErrPaths     []string
		wantClosedSubs   bool
	}{
		{
			name:         "openSubFS_emfile_falls_back_to_parent",
			openSubFSErr: syscall.EMFILE,
			wantFiles:    []string{"a/b/leaf.txt", "a/ok/keep.txt"},
		},
		{
			name:         "openSubFS_enfile_falls_back_to_parent",
			openSubFSErr: syscall.ENFILE,
			wantFiles:    []string{"a/b/leaf.txt", "a/ok/keep.txt"},
		},
		{
			name:            "readDir_after_openSubFS_emfile_closes_sub_and_retries_parent",
			subFSReadDirErr: syscall.EMFILE,
			wantFiles:       []string{"a/b/leaf.txt", "a/ok/keep.txt"},
			wantClosedSubs:  true,
		},
		{
			name:            "readDir_after_openSubFS_enfile_closes_sub_and_retries_parent",
			subFSReadDirErr: syscall.ENFILE,
			wantFiles:       []string{"a/b/leaf.txt", "a/ok/keep.txt"},
			wantClosedSubs:  true,
		},
		{
			name:           "first_next_after_openSubFS_emfile_closes_sub_and_retries_parent",
			subFSNextErr:   syscall.EMFILE,
			wantFiles:      []string{"a/b/leaf.txt", "a/ok/keep.txt"},
			wantClosedSubs: true,
		},
		{
			name:             "first_next_and_parent_fallback_emfile_reports_error_without_panic",
			failSubTarget:    "a/b",
			subFSNextErr:     syscall.EMFILE,
			parentReadDirErr: syscall.EMFILE,
			wantFiles:        []string{"a/ok/keep.txt"},
			wantErrPaths:     []string{"a/b"},
			wantClosedSubs:   true,
		},
		{
			name:          "openSubFS_permission_denied_is_not_swallowed",
			openSubFSErr:  fs.ErrPermission,
			failSubTarget: "a/b",
			wantFiles:     []string{"a/ok/keep.txt"},
			wantErrPaths:  []string{"a/b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := &emfileFallbackFS{
				base:             base,
				openSubFSErr:     tt.openSubFSErr,
				failSubTarget:    tt.failSubTarget,
				subFSReadDirErr:  tt.subFSReadDirErr,
				subFSNextErr:     tt.subFSNextErr,
				parentReadDirErr: tt.parentReadDirErr,
			}

			var files, errPaths []string
			err := WalkDirUnsorted(fsys, ".", func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					errPaths = append(errPaths, p)
					var pe *fs.PathError
					if !errors.As(err, &pe) || pe.Path != p {
						t.Errorf("error for %q has PathError %v, want Path == %q", p, pe, p)
					}
					return fs.SkipDir
				}
				if !d.IsDir() {
					files = append(files, p)
				}
				return nil
			}, nil)
			if err != nil {
				t.Fatalf("WalkDirUnsorted: %v", err)
			}

			slices.Sort(files)
			if !slices.Equal(files, tt.wantFiles) {
				t.Errorf("files = %v, want %v", files, tt.wantFiles)
			}
			if !slices.Equal(errPaths, tt.wantErrPaths) {
				t.Errorf("errPaths = %v, want %v", errPaths, tt.wantErrPaths)
			}
			if tt.wantClosedSubs {
				if len(fsys.openedSubs) == 0 {
					t.Fatal("expected at least one subFS to be opened")
				}
				for i, sub := range fsys.openedSubs {
					if !sub.closed {
						t.Errorf("openedSubs[%d] was not closed after EMFILE/ENFILE fallback", i)
					}
				}
			}
		})
	}
}
