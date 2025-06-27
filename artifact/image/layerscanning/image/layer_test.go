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
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakev1layer"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestConvertV1Layer(t *testing.T) {
	tests := []struct {
		name      string
		v1Layer   v1.Layer
		command   string
		isEmpty   bool
		wantLayer *Layer
	}{
		{
			name:    "valid layer",
			v1Layer: fakev1layer.New(t, "abc123", "ADD file", false, nil, false),
			command: "ADD file",
			isEmpty: false,
			wantLayer: &Layer{
				diffID:       "sha256:abc123",
				buildCommand: "ADD file",
				isEmpty:      false,
				fileNodeTree: NewNode(DefaultMaxSymlinkDepth),
			},
		},
		{
			name:    "valid layer with missing diff ID",
			v1Layer: fakev1layer.New(t, "", "ADD file", false, nil, false),
			command: "ADD file",
			isEmpty: false,
			wantLayer: &Layer{
				diffID:       "",
				buildCommand: "ADD file",
				isEmpty:      false,
				fileNodeTree: NewNode(DefaultMaxSymlinkDepth),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLayer := convertV1Layer(tc.v1Layer, tc.command, tc.isEmpty, DefaultMaxSymlinkDepth)

			if diff := cmp.Diff(gotLayer, tc.wantLayer, cmp.AllowUnexported(Layer{}, fakev1layer.FakeV1Layer{}, virtualFile{}, Node{})); tc.wantLayer != nil && diff != "" {
				t.Errorf("convertV1Layer(%v, %v, %v) returned layer: %v, want layer: %v", tc.v1Layer, tc.command, tc.isEmpty, gotLayer, tc.wantLayer)
			}
		})
	}
}

func TestChainLayerFS(t *testing.T) {
	root := &virtualFile{
		virtualPath: "/",
		isWhiteout:  false,
		mode:        fs.ModeDir | dirPermission,
	}
	file1 := &virtualFile{
		virtualPath: "/file1",
		isWhiteout:  false,
		mode:        filePermission,
	}

	emptyTree := func() *RootNode {
		tree := NewNode(DefaultMaxSymlinkDepth)
		_ = tree.Insert("/", root)
		return tree
	}()
	nonEmptyTree := func() *RootNode {
		tree := NewNode(DefaultMaxSymlinkDepth)
		_ = tree.Insert("/", root)
		_ = tree.Insert("/file1", file1)
		return tree
	}()

	tests := []struct {
		name       string
		chainLayer *chainLayer
		wantPaths  []string
	}{
		{
			name: "empty chain layer",
			chainLayer: &chainLayer{
				index:        0,
				fileNodeTree: emptyTree,
			},
			wantPaths: []string{
				"/",
			},
		},
		{
			name: "chain layer with single file",
			chainLayer: &chainLayer{
				index:        0,
				fileNodeTree: nonEmptyTree,
			},
			wantPaths: []string{
				"/",
				"/file1",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chainfs := tc.chainLayer.FS()

			var gotPaths []string
			_ = fs.WalkDir(chainfs, "/", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					t.Errorf("WalkDir(%v) returned error: %v", path, err)
				}
				gotPaths = append(gotPaths, path)
				return nil
			})

			if diff := cmp.Diff(gotPaths, tc.wantPaths, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("WalkDir(%v) returned incorrect paths: got %v, want %v", tc.name, gotPaths, tc.wantPaths)
			}
		})
	}
}

func TestChainFSOpen(t *testing.T) {
	populatedChainFS := setUpChainFS(t, DefaultMaxSymlinkDepth)

	tests := []struct {
		name            string
		chainfs         FS
		path            string
		wantVirtualFile *virtualFile
		wantErr         error
	}{
		{
			name: "nonexistent tree",
			chainfs: FS{
				tree: nil,
			},
			path:    "/dir1",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "empty tree",
			chainfs: setUpEmptyChainFS(t),
			path:    "/dir1",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "open root from filled tree",
			chainfs: populatedChainFS,
			path:    "/",
			wantVirtualFile: &virtualFile{
				virtualPath: "/",
				isWhiteout:  false,
				mode:        fs.ModeDir | dirPermission,
			},
		},
		{
			name:    "open directory from filled tree",
			chainfs: populatedChainFS,
			path:    "/dir1",
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir1",
				isWhiteout:  false,
				mode:        fs.ModeDir | dirPermission,
			},
		},
		{
			name:    "open file from filled tree",
			chainfs: populatedChainFS,
			path:    "/baz",
			wantVirtualFile: &virtualFile{
				virtualPath: "/baz",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open non-root file from filled tree",
			chainfs: populatedChainFS,
			path:    "/dir1/foo",
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir1/foo",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open file with .. in path",
			chainfs: populatedChainFS,
			path:    "/dir1/../dir2/bar",
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open file with .. outside of root (This should get normalized to root)",
			chainfs: populatedChainFS,
			path:    "../../dir2/bar",
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open absolute symlink from filled tree with depth 1",
			chainfs: populatedChainFS,
			path:    "/symlink1",
			// The node the symlink points to is expected.
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open absolute symlink from filled tree with depth 2",
			chainfs: populatedChainFS,
			path:    "/symlink2",
			// The node the symlink points to is expected.
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open relative symlink from filled tree",
			chainfs: populatedChainFS,
			path:    "/symlink-relative-1",
			// The node the symlink points to is expected.
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open relative symlink 2 from filled tree",
			chainfs: populatedChainFS,
			path:    "/dir2/symlink-relative-2",
			// The node the symlink points to is expected.
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open relative symlink 3 nested from filled tree",
			chainfs: populatedChainFS,
			path:    "/dir2/symlink-relative-3",
			// The node the symlink points to is expected.
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open file that is symlinked via directory from filled tree",
			chainfs: populatedChainFS,
			path:    "/symlink-to-dir/bar",
			// "/symlink-dir" resolves to "/dir1", so we should get the virtual file with path "/dir1/foo"
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open file that is under symlink that is symlinked to another symlink directory",
			chainfs: populatedChainFS,
			path:    "/symlink-to-dir-nested/bar",
			// "/symlink-dir" resolves to "/dir1", so we should get the virtual file with path "/dir1/foo"
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "open file that is a symlink to a file that is symlinked under another symlink directory",
			chainfs: populatedChainFS,
			path:    "/symlink-into-nested-dir-symlink",
			// "/symlink-dir" resolves to "/dir1", so we should get the virtual file with path "/dir1/foo"
			wantVirtualFile: &virtualFile{
				virtualPath: "/dir2/bar",
				isWhiteout:  false,
				mode:        filePermission,
			},
		},
		{
			name:    "error opening symlink due to nonexistent target",
			chainfs: populatedChainFS,
			path:    "/symlink-to-nonexistent-file",
			wantErr: fs.ErrNotExist,
		},
		{
			name: "error opening symlink due to depth exceeded",
			chainfs: func() FS {
				chainfs := setUpChainFS(t, 3)
				return chainfs
			}(),
			path:    "/symlink4",
			wantErr: ErrSymlinkDepthExceeded,
		},
		{
			name:    "error opening symlink due to cycle",
			chainfs: populatedChainFS,
			path:    "/symlink-cycle1",
			// New method cannot determine links, just depth exceeded.
			// If symlink depths is a reasonable number it should not matter.
			wantErr: ErrSymlinkDepthExceeded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotFile, gotErr := tc.chainfs.Open(tc.path)

			if tc.wantErr != nil {
				if !errors.Is(gotErr, tc.wantErr) {
					t.Fatalf("Open(%v) returned error: %v, want error: %v", tc.path, gotErr, tc.wantErr)
				}
				return
			}

			if gotErr != nil {
				t.Fatalf("Open(%v) returned error: %v", tc.path, gotErr)
				return
			}

			if diff := cmp.Diff(gotFile, tc.wantVirtualFile, cmp.AllowUnexported(virtualFile{})); tc.wantVirtualFile != nil && diff != "" {
				t.Errorf("Open(%v) returned file: %v, want file: %v", tc.path, gotFile, tc.wantVirtualFile)
			}
		})
	}
}

func TestChainFSStat(t *testing.T) {
	populatedChainFS := setUpChainFS(t, DefaultMaxSymlinkDepth)

	tests := []struct {
		name         string
		chainfs      FS
		path         string
		wantFileInfo fakefs.FakeFileInfo
		wantErr      error
	}{
		{
			name: "nonexistent tree",
			chainfs: FS{
				tree: nil,
			},
			path:    "/dir1",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "empty tree",
			chainfs: setUpEmptyChainFS(t),
			path:    "/dir1",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "stat whiteout file",
			chainfs: populatedChainFS,
			path:    "/wh.foobar",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "stat regular file",
			chainfs: populatedChainFS,
			path:    "/baz",
			wantFileInfo: fakefs.FakeFileInfo{
				FileName: "baz",
				FileMode: filePermission,
			},
		},
		{
			name:    "stat directory",
			chainfs: populatedChainFS,
			path:    "/dir1",
			wantFileInfo: fakefs.FakeFileInfo{
				FileName: "dir1",
				FileMode: fs.ModeDir | dirPermission,
			},
		},
		{
			name:    "stat symlink to file should return details about the target file",
			chainfs: populatedChainFS,
			path:    "/symlink1",
			wantFileInfo: fakefs.FakeFileInfo{
				FileName: "bar",
				FileMode: filePermission,
			},
		},
		{
			name:    "stat file through symlinked directory",
			chainfs: populatedChainFS,
			path:    "/symlink-to-dir/bar",
			wantFileInfo: fakefs.FakeFileInfo{
				FileName: "bar",
				FileMode: filePermission,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotFileInfo, gotErr := tc.chainfs.Stat(tc.path)

			if tc.wantErr != nil {
				if !errors.Is(gotErr, tc.wantErr) {
					t.Fatalf("Stat(%v) returned error: %v, want error: %v", tc.path, gotErr, tc.wantErr)
				}
				return
			}

			if gotErr != nil {
				t.Fatalf("Stat(%v) returned error: %v", tc.path, gotErr)
			}

			if gotFileInfo.Name() != tc.wantFileInfo.Name() {
				t.Errorf("Stat(%v) returned incorrect file name: got %s, want %s", tc.path, gotFileInfo.Name(), tc.wantFileInfo.FileName)
			}
			if gotFileInfo.Mode() != tc.wantFileInfo.Mode() {
				t.Errorf("Stat(%v) returned incorrect file mode: got %v, want %v", tc.path, gotFileInfo.Mode(), tc.wantFileInfo.FileMode)
			}
		})
	}
}

func TestChainFSReadDir(t *testing.T) {
	populatedChainFS := setUpChainFS(t, DefaultMaxSymlinkDepth)

	tests := []struct {
		name             string
		chainfs          FS
		path             string
		wantVirtualFiles []*virtualFile
		wantErr          error
	}{
		{
			name: "read directory from nonexistent tree",
			chainfs: FS{
				tree: nil,
			},
			path:    "/dir1",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "root directory",
			chainfs: setUpEmptyChainFS(t),
			path:    "/",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "non-root directory in empty tree",
			chainfs: setUpEmptyChainFS(t),
			path:    "/dir1",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "read root directory from filled tree",
			chainfs: populatedChainFS,
			path:    "/",
			// wh.foobar is a whiteout file and should not be returned.
			wantVirtualFiles: []*virtualFile{
				{
					virtualPath: "/dir1",
					isWhiteout:  false,
					mode:        fs.ModeDir | dirPermission,
				},
				{
					virtualPath: "/baz",
					isWhiteout:  false,
					mode:        filePermission,
				},
				{
					virtualPath: "/dir2",
					isWhiteout:  false,
					mode:        fs.ModeDir | dirPermission,
				},
				{
					virtualPath: "/symlink1",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/dir2/bar",
				},
				{
					virtualPath: "/symlink2",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/symlink1",
				},
				{
					virtualPath: "/symlink3",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/symlink2",
				},
				{
					virtualPath: "/symlink4",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/symlink3",
				},
				{
					virtualPath: "/symlink-into-nested-dir-symlink",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/symlink-to-dir-nested/bar",
				},
				{
					virtualPath: "/symlink-relative-1",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "./dir2/bar",
				},
				{
					virtualPath: "/symlink-cycle1",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/symlink-cycle2",
				},
				{
					virtualPath: "/symlink-cycle2",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/symlink-cycle3",
				},
				{
					virtualPath: "/symlink-cycle3",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/symlink-cycle1",
				},
				{
					virtualPath: "/symlink-to-dir-nested",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/symlink-to-dir",
				},
				{
					virtualPath: "/symlink-to-nonexistent-file",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/nonexistent-file",
				},
				{
					virtualPath: "/symlink-to-dir",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "/dir2",
				},
			},
		},
		{
			name:    "read non-root directory from filled tree",
			chainfs: populatedChainFS,
			path:    "/dir1",
			wantVirtualFiles: []*virtualFile{
				{
					virtualPath: "/dir1/foo",
					isWhiteout:  false,
					mode:        filePermission,
				},
			},
		},
		{
			name:    "readdir file node leaf from filled tree should return error",
			chainfs: populatedChainFS,
			path:    "/dir1/foo",
			wantErr: fs.ErrInvalid,
		},
		{
			name:    "read symlink from filled tree",
			chainfs: populatedChainFS,
			path:    "/symlink-to-dir",
			wantVirtualFiles: []*virtualFile{
				{
					virtualPath: "/dir2/bar",
					isWhiteout:  false,
					mode:        filePermission,
				},
				{
					virtualPath: "/dir2/symlink-relative-2",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "./bar",
				},
				{
					virtualPath: "/dir/symlink-relative-3",
					isWhiteout:  false,
					mode:        fs.ModeSymlink,
					targetPath:  "../symlink-relative-1",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotDirEntries, gotErr := tc.chainfs.ReadDir(tc.path)

			if tc.wantErr != nil {
				if !errors.Is(gotErr, tc.wantErr) {
					t.Fatalf("ReadDir(%v) returned error: %v, want error: %v", tc.path, gotErr, tc.wantErr)
				}
				return
			}

			if gotErr != nil {
				t.Fatalf("ReadDir(%v) returned error: %v", tc.path, gotErr)
				return
			}

			// Convert fileNodes to DirEntries for comparison.
			wantDirEntries := make([]fs.DirEntry, 0, len(tc.wantVirtualFiles))
			for _, node := range tc.wantVirtualFiles {
				wantDirEntries = append(wantDirEntries, node)
			}

			if len(wantDirEntries) != len(gotDirEntries) {
				t.Errorf("ReadDir(%v) returned incorrect number of dir entries: got %d dir entries, want %d dir entries", tc.path, len(gotDirEntries), len(wantDirEntries))
			}

			// Sort the directory entries by filename, as is required by the fs.ReadDirFS interface.
			slices.SortFunc(wantDirEntries, func(a, b fs.DirEntry) int {
				return strings.Compare(a.Name(), b.Name())
			})

			for i := range wantDirEntries {
				gotEntry := gotDirEntries[i]
				wantEntry := wantDirEntries[i]
				if gotEntry.Name() != wantEntry.Name() {
					t.Errorf("ReadDir(%v) returned incorrect dir entry name: got %s, want %s", tc.path, gotEntry.Name(), wantEntry.Name())
				}
				if gotEntry.IsDir() != wantEntry.IsDir() {
					t.Errorf("ReadDir(%v) returned incorrect dir entry isDir: got %t, want %t", tc.path, gotEntry.IsDir(), wantEntry.IsDir())
				}
				if gotEntry.Type() != wantEntry.Type() {
					t.Errorf("ReadDir(%v) returned incorrect dir entry type: got %v, want %v", tc.path, gotEntry.Type(), wantEntry.Type())
				}
				// The fileInfo from DirEntry is retrieved by calling Stat() on the fileNode. Stat() has
				// its own tests, so we can skip checking the fileInfo here.
			}
		})
	}
}

// ========================================================
// CHAINLAYER TESTING HELPER METHODS
// ========================================================

func setUpEmptyChainFS(t *testing.T) FS {
	t.Helper()

	return FS{
		tree: NewNode(DefaultMaxSymlinkDepth),
	}
}

// setUpChainFS creates a chainFS with a populated tree and creates the corresponding files in a
// temporary directory. It returns the chainFS and the temporary directory path.
func setUpChainFS(t *testing.T, maxSymlinkDepth int) FS {
	t.Helper()

	chainfs := FS{
		tree: NewNode(maxSymlinkDepth),
	}

	vfsMap := map[string]*virtualFile{
		// Layer 1 files / directories
		"/": &virtualFile{
			virtualPath: "/",
			isWhiteout:  false,
			mode:        fs.ModeDir | dirPermission,
		},
		"/dir1": &virtualFile{
			virtualPath: "/dir1",
			isWhiteout:  false,
			mode:        fs.ModeDir | dirPermission,
		},
		"/baz": &virtualFile{
			virtualPath: "/baz",
			isWhiteout:  false,
			mode:        filePermission,
		},
		// Layer 2 files / directories
		"/dir1/foo": &virtualFile{
			virtualPath: "/dir1/foo",
			isWhiteout:  false,
			mode:        filePermission,
		},
		"/dir2": &virtualFile{
			virtualPath: "/dir2",
			isWhiteout:  false,
			mode:        fs.ModeDir | dirPermission,
		},
		"/dir2/bar": &virtualFile{
			virtualPath: "/dir2/bar",
			isWhiteout:  false,
			mode:        filePermission,
		},
		"/wh.foobar": &virtualFile{
			virtualPath: "/wh.foobar",
			isWhiteout:  true,
			mode:        filePermission,
		},
		"/symlink1": &virtualFile{
			virtualPath: "/symlink1",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/dir2/bar",
		},
		"/symlink2": &virtualFile{
			virtualPath: "/symlink2",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/symlink1",
		},
		"/symlink3": &virtualFile{
			virtualPath: "/symlink3",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/symlink2",
		},
		"/symlink4": &virtualFile{
			virtualPath: "/symlink4",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/symlink3",
		},
		"/symlink-relative-1": &virtualFile{
			virtualPath: "/symlink-relative-1",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "./dir2/bar",
		},
		"/dir2/symlink-relative-2": &virtualFile{
			virtualPath: "/dir2/symlink-relative-2",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "./bar",
		},
		"/dir2/symlink-relative-3": &virtualFile{
			virtualPath: "/dir2/symlink-relative-3",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "../symlink-relative-1",
		},
		"/symlink-to-dir-nested": &virtualFile{
			virtualPath: "/symlink-to-dir-nested",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/symlink-to-dir",
		},
		"/symlink-into-nested-dir-symlink": &virtualFile{
			virtualPath: "/symlink-into-nested-dir-symlink",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/symlink-to-dir-nested/bar",
		},
		"/symlink-to-dir": &virtualFile{
			virtualPath: "/symlink-to-dir",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/dir2",
		},
		"/symlink-to-nonexistent-file": &virtualFile{
			virtualPath: "/symlink-to-nonexistent-file",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/nonexistent-file",
		},
		"/symlink-cycle1": &virtualFile{
			virtualPath: "/symlink-cycle1",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/symlink-cycle2",
		},
		"/symlink-cycle2": &virtualFile{
			virtualPath: "/symlink-cycle2",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/symlink-cycle3",
		},
		"/symlink-cycle3": &virtualFile{
			virtualPath: "/symlink-cycle3",
			isWhiteout:  false,
			mode:        fs.ModeSymlink,
			targetPath:  "/symlink-cycle1",
		},
	}

	for path, vf := range vfsMap {
		_ = chainfs.tree.Insert(path, vf)
	}

	return chainfs
}
