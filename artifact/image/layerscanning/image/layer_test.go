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
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakev1layer"
	"github.com/google/osv-scalibr/artifact/image/pathtree"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestConvertV1Layer(t *testing.T) {
	reader := io.NopCloser(nil)
	tests := []struct {
		name      string
		v1Layer   v1.Layer
		command   string
		isEmpty   bool
		wantLayer *Layer
		wantError error
	}{
		{
			name:    "valid layer",
			v1Layer: fakev1layer.New("abc123", "ADD file", false, reader),
			command: "ADD file",
			isEmpty: false,
			wantLayer: &Layer{
				v1Layer:      fakev1layer.New("abc123", "ADD file", false, reader),
				diffID:       "sha256:abc123",
				buildCommand: "ADD file",
				isEmpty:      false,
				fileNodeTree: pathtree.NewNode[fileNode](),
			},
		},
		{
			name:      "v1 layer missing diffID",
			v1Layer:   fakev1layer.New("", "ADD file", false, reader),
			command:   "ADD file",
			isEmpty:   false,
			wantError: ErrDiffIDMissingFromLayer,
		},
		{
			name:      "v1 layer missing tar reader",
			v1Layer:   fakev1layer.New("abc123", "ADD file", false, nil),
			command:   "ADD file",
			isEmpty:   false,
			wantError: ErrUncompressedReaderMissingFromLayer,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLayer, gotError := convertV1Layer(tc.v1Layer, tc.command, tc.isEmpty)

			if tc.wantError != nil && gotError == tc.wantError {
				t.Errorf("convertV1Layer(%v, %v, %v) returned error: %v, want error: %v", tc.v1Layer, tc.command, tc.isEmpty, gotError, tc.wantError)
			}
			if diff := cmp.Diff(gotLayer, tc.wantLayer, cmp.AllowUnexported(Layer{}, fakev1layer.FakeV1Layer{}, pathtree.Node[fileNode]{})); tc.wantLayer != nil && diff != "" {
				t.Errorf("convertV1Layer(%v, %v, %v) returned layer: %v, want layer: %v", tc.v1Layer, tc.command, tc.isEmpty, gotLayer, tc.wantLayer)
			}
		})
	}
}

func TestChainLayerFS(t *testing.T) {
	testDir := func() string {
		dir := t.TempDir()
		os.WriteFile(path.Join(dir, "file1"), []byte("file1"), 0600)
		return dir
	}()

	root := &fileNode{
		extractDir:    testDir,
		originLayerID: "",
		virtualPath:   "/",
		isWhiteout:    false,
		mode:          fs.ModeDir | dirPermission,
	}
	file1 := &fileNode{
		extractDir:    testDir,
		originLayerID: "",
		virtualPath:   "/file1",
		isWhiteout:    false,
		mode:          filePermission,
	}

	emptyTree := func() *pathtree.Node[fileNode] {
		tree := pathtree.NewNode[fileNode]()
		tree.Insert("/", root)
		return tree
	}()
	nonEmptyTree := func() *pathtree.Node[fileNode] {
		tree := pathtree.NewNode[fileNode]()
		tree.Insert("/", root)
		tree.Insert("/file1", file1)
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

			gotPaths := []string{}
			fs.WalkDir(chainfs, "/", func(path string, d fs.DirEntry, err error) error {
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
	populatedChainFS, extractDir := setUpChainFS(t, 3)

	tests := []struct {
		name     string
		chainfs  FS
		path     string
		wantNode *fileNode
		wantErr  error
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
			wantNode: &fileNode{
				extractDir:    extractDir,
				originLayerID: "layer1",
				virtualPath:   "/",
				isWhiteout:    false,
				mode:          fs.ModeDir | dirPermission,
			},
		},
		{
			name:    "open directory from filled tree",
			chainfs: populatedChainFS,
			path:    "/dir1",
			wantNode: &fileNode{
				extractDir:    extractDir,
				originLayerID: "layer1",
				virtualPath:   "/dir1",
				isWhiteout:    false,
				mode:          fs.ModeDir | dirPermission,
			},
		},
		{
			name:    "open file from filled tree",
			chainfs: populatedChainFS,
			path:    "/baz",
			wantNode: &fileNode{
				extractDir:    extractDir,
				originLayerID: "layer1",
				virtualPath:   "/baz",
				isWhiteout:    false,
				mode:          filePermission,
			},
		},
		{
			name:    "open non-root file from filled tree",
			chainfs: populatedChainFS,
			path:    "/dir1/foo",
			wantNode: &fileNode{
				extractDir:    extractDir,
				originLayerID: "layer2",
				virtualPath:   "/dir1/foo",
				isWhiteout:    false,
				mode:          filePermission,
			},
		},
		{
			name:    "open absolute symlink from filled tree with depth 1",
			chainfs: populatedChainFS,
			path:    "/symlink1",
			// The node the symlink points to is expected.
			wantNode: &fileNode{
				extractDir:    extractDir,
				originLayerID: "layer2",
				virtualPath:   "/dir2/bar",
				isWhiteout:    false,
				mode:          filePermission,
			},
		},
		{
			name:    "open absolute symlink from filled tree with depth 2",
			chainfs: populatedChainFS,
			path:    "/symlink2",
			// The node the symlink points to is expected.
			wantNode: &fileNode{
				extractDir:    extractDir,
				originLayerID: "layer2",
				virtualPath:   "/dir2/bar",
				isWhiteout:    false,
				mode:          filePermission,
			},
		},
		{
			name:    "error opening symlink due to nonexistent target",
			chainfs: populatedChainFS,
			path:    "/symlink-to-nonexistent-file",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "error opening symlink due to depth exceeded",
			chainfs: populatedChainFS,
			path:    "/symlink4",
			wantErr: ErrSymlinkDepthExceeded,
		},
		{
			name:    "error opening symlink due to cycle",
			chainfs: populatedChainFS,
			path:    "/symlink-cycle1",
			wantErr: ErrSymlinkCycle,
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

			if diff := cmp.Diff(gotFile, tc.wantNode, cmp.AllowUnexported(fileNode{})); tc.wantNode != nil && diff != "" {
				t.Errorf("Open(%v) returned file: %v, want file: %v", tc.path, gotFile, tc.wantNode)
			}
		})
	}
}

func TestChainFSStat(t *testing.T) {
	populatedChainFS, _ := setUpChainFS(t, DefaultMaxSymlinkDepth)

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
		// TODO: b/377553505 - Add more tests for Stat() that involve more complex file structures.
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
	populatedChainFS, extractDir := setUpChainFS(t, DefaultMaxSymlinkDepth)

	tests := []struct {
		name      string
		chainfs   FS
		path      string
		wantNodes []*fileNode
		wantErr   error
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
			wantNodes: []*fileNode{
				{
					extractDir:    extractDir,
					originLayerID: "layer1",
					virtualPath:   "/dir1",
					isWhiteout:    false,
					mode:          fs.ModeDir | dirPermission,
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer1",
					virtualPath:   "/baz",
					isWhiteout:    false,
					mode:          filePermission,
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/dir2",
					isWhiteout:    false,
					mode:          fs.ModeDir | dirPermission,
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink1",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/dir2/bar",
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink2",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/symlink1",
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink3",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/symlink2",
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink4",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/symlink3",
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink-cycle1",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/symlink-cycle2",
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink-cycle2",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/symlink-cycle3",
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink-cycle3",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/symlink-cycle1",
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink-to-nonexistent-file",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/nonexistent-file",
				},
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/symlink-to-dir",
					isWhiteout:    false,
					mode:          fs.ModeSymlink,
					targetPath:    "/dir2",
				},
			},
		},
		{
			name:    "read non-root directory from filled tree",
			chainfs: populatedChainFS,
			path:    "/dir1",
			wantNodes: []*fileNode{
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/dir1/foo",
					isWhiteout:    false,
					mode:          filePermission,
				},
			},
		},
		{
			name:      "read file node leaf from filled tree",
			chainfs:   populatedChainFS,
			path:      "/dir1/foo",
			wantNodes: []*fileNode{},
		},
		{
			name:    "read symlink from filled tree",
			chainfs: populatedChainFS,
			path:    "/symlink-to-dir",
			wantNodes: []*fileNode{
				{
					extractDir:    extractDir,
					originLayerID: "layer2",
					virtualPath:   "/dir2/bar",
					isWhiteout:    false,
					mode:          filePermission,
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
			wantDirEntries := make([]fs.DirEntry, 0, len(tc.wantNodes))
			for _, node := range tc.wantNodes {
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

func checkError(t *testing.T, funcName string, gotErr error, wantErr error) {
	t.Helper()
	if wantErr != nil {
		if !errors.Is(gotErr, wantErr) {
			t.Fatalf("%s returned error: %v, want error: %v", funcName, gotErr, wantErr)
		}
		return
	}

	if gotErr != nil {
		t.Fatalf("%s returned error: %v", funcName, gotErr)
		return
	}
}

func setUpEmptyChainFS(t *testing.T) FS {
	t.Helper()

	return FS{
		tree:            pathtree.NewNode[fileNode](),
		maxSymlinkDepth: DefaultMaxSymlinkDepth,
	}
}

// setUpChainFS creates a chainFS with a populated tree and creates the corresponding files in a
// temporary directory. It returns the chainFS and the temporary directory path.
func setUpChainFS(t *testing.T, maxSymlinkDepth int) (FS, string) {
	t.Helper()
	tempDir := t.TempDir()

	chainfs := FS{
		tree:            pathtree.NewNode[fileNode](),
		maxSymlinkDepth: maxSymlinkDepth,
	}

	vfsMap := map[string]*fileNode{
		// Layer 1 files / directories
		"/": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer1",
			virtualPath:   "/",
			isWhiteout:    false,
			mode:          fs.ModeDir | dirPermission,
		},
		"/dir1": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer1",
			virtualPath:   "/dir1",
			isWhiteout:    false,
			mode:          fs.ModeDir | dirPermission,
		},
		"/baz": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer1",
			virtualPath:   "/baz",
			isWhiteout:    false,
			mode:          filePermission,
		},
		// Layer 2 files / directories
		"/dir1/foo": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "/dir1/foo",
			isWhiteout:    false,
			mode:          filePermission,
		},
		"/dir2": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "/dir2",
			isWhiteout:    false,
			mode:          fs.ModeDir | dirPermission,
		},
		"/dir2/bar": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "/dir2/bar",
			isWhiteout:    false,
			mode:          filePermission,
		},
		"/wh.foobar": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "/wh.foobar",
			isWhiteout:    true,
			mode:          filePermission,
		},
		"/symlink1": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "/symlink1",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/dir2/bar",
		},
		"/symlink2": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "symlink2",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/symlink1",
		},
		"/symlink3": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "symlink3",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/symlink2",
		},
		"/symlink4": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "symlink4",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/symlink3",
		},
		"/symlink-to-dir": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "symlink-to-dir",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/dir2",
		},
		"/symlink-to-nonexistent-file": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "symlink-to-nonexistent-file",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/nonexistent-file",
		},
		"/symlink-cycle1": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "symlink-cycle1",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/symlink-cycle2",
		},
		"/symlink-cycle2": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "symlink-cycle2",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/symlink-cycle3",
		},
		"/symlink-cycle3": &fileNode{
			extractDir:    tempDir,
			originLayerID: "layer2",
			virtualPath:   "symlink-cycle3",
			isWhiteout:    false,
			mode:          fs.ModeSymlink,
			targetPath:    "/symlink-cycle1",
		},
	}

	for path, node := range vfsMap {
		chainfs.tree.Insert(path, node)

		if node.IsDir() {
			os.MkdirAll(node.RealFilePath(), dirPermission)
		} else {
			if node.mode == fs.ModeSymlink {
				continue
			}
			os.WriteFile(node.RealFilePath(), []byte(path), filePermission)
		}
	}
	return chainfs, tempDir
}
