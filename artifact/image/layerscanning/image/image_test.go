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
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakev1layer"
	"github.com/google/osv-scalibr/artifact/image/pathtree"
	"github.com/google/osv-scalibr/artifact/image/require"
)

const testdataDir = "testdata"

type filepathContentPair struct {
	filepath string
	content  string
}
type chainLayerEntries struct {
	// Some chain layers can be ignored for the purposes of testing.
	ignore               bool
	filepathContentPairs []filepathContentPair
}

type fakeV1Image struct {
	layers            []v1.Layer
	config            *v1.ConfigFile
	errorOnLayers     bool
	errorOnConfigFile bool
}

func (fakeV1Image *fakeV1Image) Layers() ([]v1.Layer, error) {
	if fakeV1Image.errorOnLayers {
		return nil, fmt.Errorf("error on layers")
	}
	return fakeV1Image.layers, nil
}

func (fakeV1Image *fakeV1Image) ConfigFile() (*v1.ConfigFile, error) {
	if fakeV1Image.errorOnConfigFile {
		return nil, fmt.Errorf("error on config file")
	}
	return fakeV1Image.config, nil
}

func (fakeV1Image *fakeV1Image) MediaType() (types.MediaType, error) {
	return "", nil
}

func (fakeV1Image *fakeV1Image) Size() (int64, error) {
	return 0, nil
}

func (fakeV1Image *fakeV1Image) ConfigName() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (fakeV1Image *fakeV1Image) RawConfigFile() ([]byte, error) {
	return nil, nil
}

func (fakeV1Image *fakeV1Image) Digest() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (fakeV1Image *fakeV1Image) Manifest() (*v1.Manifest, error) {
	return nil, nil
}

func (fakeV1Image *fakeV1Image) RawManifest() ([]byte, error) {
	return nil, nil
}

func (fakeV1Image *fakeV1Image) LayerByDigest(v1.Hash) (v1.Layer, error) {
	return nil, nil
}

func (fakeV1Image *fakeV1Image) LayerByDiffID(v1.Hash) (v1.Layer, error) {
	return nil, nil
}

// Testing plan:
//
// Basic Cases:
//  1. Create a scratch image with a single layer that adds a file. There should be one layer with
//     one file.
//  2. Create a scratch image with two layers. The first layer adds a file, the second layer adds a
//     different file. The second chain layer should have two files.
//  3. Create a scratch image with two layers. The first layer adds a file, the second layer
//     overwrites that file with a different file. The second chain layer should have one file.
//  4. Create a scratch image with two layers. The first layer adds a file, the second layer
//     deletes that file. The second chain layer should have no files.
//  5. Create a scratch image with two layers. The first layer adds a file, the second layer
//     adds two different files. The second chain layer should have three files.
//  6. Create a scratch image with three layers. The first layer adds file X, the second layer
//     deletes file X, and the third layer adds file X back. The second chain layer should
//     have no files, and the third chain layer should have file X.
//
// Symlink Cases:
//  1. Create a scratch image with one layer. The layer contains a regular file and two symlinks (A
//     and B). The symlink chain is A -> B -> file.
//  2. Create an image that has a symlink chain whose size is greater than the max symlink depth.
//     An error should be returned.
//  3. Create an image that has a symlink cycle. An error should be returned.
//  4. Create an image that has a dangling symlink.
//  5. Create an image that has a symlink that point to a file outside of the virtual root.
func TestFromTarball(t *testing.T) {
	tests := []struct {
		name                       string
		tarPath                    string
		config                     *Config
		wantChainLayerEntries      []chainLayerEntries
		wantErrDuringImageCreation error
		wantErrWhileReadingFiles   error
	}{
		{
			name:    "invalid config - non positive maxFileBytes",
			tarPath: filepath.Join(testdataDir, "single-file.tar"),
			config: &Config{
				Requirer:     &require.FileRequirerAll{},
				MaxFileBytes: 0,
			},
			wantErrDuringImageCreation: ErrInvalidConfig,
		},
		{
			name:    "invalid config - missing requirer",
			tarPath: filepath.Join(testdataDir, "single-file.tar"),
			config: &Config{
				MaxFileBytes: DefaultMaxFileBytes,
			},
			wantErrDuringImageCreation: ErrInvalidConfig,
		},
		{
			name:    "image with one file",
			tarPath: filepath.Join(testdataDir, "single-file.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "foo.txt",
							content:  "foo\n",
						},
					},
				},
			},
		},
		{
			name:    "image with two files",
			tarPath: filepath.Join(testdataDir, "basic.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "sample.txt",
							content:  "sample text file\n",
						},
					},
				},
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "larger-sample.txt",
							content:  strings.Repeat("sample text file\n", 400),
						},
						{
							filepath: "sample.txt",
							content:  "sample text file\n",
						},
					},
				},
			},
		},
		{
			name:    "second layer overwrites file with different content",
			tarPath: filepath.Join(testdataDir, "overwrite-file.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "sample.txt",
							content:  "sample text file\n",
						},
					},
				},
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "sample.txt",
							content:  "overwritten sample text file\n",
						},
					},
				},
			},
		},
		{
			name:    "second layer deletes file",
			tarPath: filepath.Join(testdataDir, "delete-file.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					ignore:               true,
					filepathContentPairs: []filepathContentPair{},
				},
				{
					ignore:               true,
					filepathContentPairs: []filepathContentPair{},
				},
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "sample.txt",
							content:  "sample text file\n",
						},
					},
				},
				{
					filepathContentPairs: []filepathContentPair{},
				},
			},
		},
		{
			name:    "multiple files and directories added across layers",
			tarPath: filepath.Join(testdataDir, "multiple-files.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "foo.txt",
							content:  "foo\n",
						},
					},
				},
				{
					// dir1/bar.txt and dir1/baz.txt are added in the second layer.
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "foo.txt",
							content:  "foo\n",
						},
						{
							filepath: "dir1/bar.txt",
							content:  "bar\n",
						},
						{
							filepath: "dir1/baz.txt",
							content:  "baz\n",
						},
					},
				},
			},
		},
		{
			name:    "file is deleted and later added back",
			tarPath: filepath.Join(testdataDir, "recreate-file.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					ignore:               true,
					filepathContentPairs: []filepathContentPair{},
				},
				{
					ignore:               true,
					filepathContentPairs: []filepathContentPair{},
				},
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "sample.txt",
							content:  "sample text file\n",
						},
					},
				},
				{
					filepathContentPairs: []filepathContentPair{},
				},
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "sample.txt",
							content:  "sample text file\n",
						},
					},
				},
			},
		},
		{
			name:    "image with file surpassing max file size",
			tarPath: filepath.Join(testdataDir, "single-file.tar"),
			config: &Config{
				MaxFileBytes: 1,
				Requirer:     &require.FileRequirerAll{},
			},
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "foo.txt",
							content:  "foo\n",
						},
					},
				},
			},
			// Reading foo.txt should return an error, since it exceeds the max file size and should not
			// be stored in the chain layer.
			wantErrWhileReadingFiles: fs.ErrNotExist,
		},
		{
			name:    "image with relative, absolute, and chain symlinks",
			tarPath: filepath.Join(testdataDir, "symlink-basic.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "dir1/sample.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/absolute-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/relative-dot-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/relative-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/chain-symlink.txt",
							content:  "sample text\n",
						},
					},
				},
			},
		},
		{
			name:    "image with required symlink but non-required target path",
			tarPath: filepath.Join(testdataDir, "symlink-basic.tar"),
			config: &Config{
				MaxFileBytes:    DefaultMaxFileBytes,
				MaxSymlinkDepth: DefaultMaxSymlinkDepth,
				// dir1/sample.txt is not explicitly required, but should be unpacked because it is the
				// target of a required symlink.
				Requirer: require.NewFileRequirerPaths([]string{
					"/dir1/absolute-symlink.txt",
				}),
			},
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "dir1/sample.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/absolute-symlink.txt",
							content:  "sample text\n",
						},
					},
				},
			},
		},
		{
			name:    "image with symlink chain but non-required target path",
			tarPath: filepath.Join(testdataDir, "symlink-basic.tar"),
			config: &Config{
				MaxFileBytes:    DefaultMaxFileBytes,
				MaxSymlinkDepth: DefaultMaxSymlinkDepth,
				Requirer: require.NewFileRequirerPaths([]string{
					"/dir1/chain-symlink.txt",
				}),
			},
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "dir1/sample.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/absolute-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/chain-symlink.txt",
							content:  "sample text\n",
						},
					},
				},
			},
		},
		{
			name:    "image with symlink cycle",
			tarPath: filepath.Join(testdataDir, "symlink-cycle.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "dir1/sample.txt",
						},
						{
							filepath: "dir1/absolute-symlink.txt",
						},
						{
							filepath: "dir1/chain-symlink.txt",
						},
					},
				},
			},
			wantErrWhileReadingFiles: ErrSymlinkCycle,
		},
		{
			name:    "image with symlink depth exceeded",
			tarPath: filepath.Join(testdataDir, "symlink-depth-exceeded.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "dir1/symlink7.txt",
							content:  "sample text\n",
						},
					},
				},
			},
			wantErrWhileReadingFiles: ErrSymlinkDepthExceeded,
		},
		{
			name:    "image with dangling symlinks",
			tarPath: filepath.Join(testdataDir, "symlink-dangling.tar"),
			config:  DefaultConfig(),
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "dir1/absolute-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/relative-dot-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/relative-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir1/chain-symlink.txt",
							content:  "sample text\n",
						},
					},
				},
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "dir2/dir3/relative-subfolder-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir2/dir3/absolute-subfolder-symlink.txt",
							content:  "sample text\n",
						},
						{
							filepath: "dir2/dir3/absolute-chain-symlink.txt",
							content:  "sample text\n",
						},
					},
				},
			},
			wantErrWhileReadingFiles: fs.ErrNotExist,
		},
		{
			name:                       "image with symlink pointing outside of root",
			tarPath:                    filepath.Join(testdataDir, "symlink-attack.tar"),
			config:                     DefaultConfig(),
			wantErrDuringImageCreation: ErrSymlinkPointsOutsideRoot,
		},
		{
			name:    "require single file from images",
			tarPath: filepath.Join(testdataDir, "multiple-files.tar"),
			config: &Config{
				MaxFileBytes: DefaultMaxFileBytes,
				// Only require foo.txt.
				Requirer: require.NewFileRequirerPaths([]string{"/foo.txt"}),
			},
			wantChainLayerEntries: []chainLayerEntries{
				{
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "foo.txt",
							content:  "foo\n",
						},
					},
				},
				{
					// dir1/bar.txt and dir1/baz.txt are ignored in the second layer.
					filepathContentPairs: []filepathContentPair{
						{
							filepath: "foo.txt",
							content:  "foo\n",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotImage, gotErr := FromTarball(tc.tarPath, tc.config)

			if tc.wantErrDuringImageCreation != nil {
				if errors.Is(gotErr, tc.wantErrDuringImageCreation) {
					return
				}
				t.Fatalf("FromTarball(%v) returned error: %v, want error: %v", tc.tarPath, gotErr, tc.wantErrDuringImageCreation)
			}

			if gotErr != nil {
				t.Fatalf("FromTarball(%v) returned unexpected error: %v", tc.tarPath, gotErr)
			}
			// Only defer call to CleanUp if the image was created successfully.
			defer gotImage.CleanUp()

			// Make sure the expected files are in the chain layers.
			chainLayers, err := gotImage.ChainLayers()
			if err != nil {
				t.Fatalf("ChainLayers() returned error: %v", err)
			}

			// If the number of chain layers does not match the number of expected chain layer entries,
			// then there is no point in continuing the test.
			if len(chainLayers) != len(tc.wantChainLayerEntries) {
				t.Fatalf("ChainLayers() returned incorrect number of chain layers: got %d chain layers, want %d chain layers", len(chainLayers), len(tc.wantChainLayerEntries))
			}

			for i := range chainLayers {
				chainLayer := chainLayers[i]
				wantChainLayerEntries := tc.wantChainLayerEntries[i]

				if wantChainLayerEntries.ignore {
					continue
				}

				compareChainLayerEntries(t, chainLayer, wantChainLayerEntries, tc.wantErrWhileReadingFiles)
			}
		})
	}
}

// Testing plan:
//  1. Use a fake v1.Image that has no config file. Make sure that Load() returns an error.
//  2. Use a fake v1.Image that returns an error when calling Layers(). Make sure that Load() returns
//     an error.
//  3. Create an image with a file surpassing the max file size. Make sure that Load() returns
//     an error.
//  4. Devise a pathtree that will return an error when inserting a path. Make sure that Load()
//     returns an error.
func TestFromV1Image(t *testing.T) {
	tests := []struct {
		name                  string
		v1Image               v1.Image
		wantChainLayerEntries []chainLayerEntries
		wantErr               bool
		wantPanic             bool
	}{
		{
			name: "image with no config file",
			v1Image: &fakeV1Image{
				errorOnConfigFile: true,
			},
			wantErr: true,
		},
		{
			name: "image with error on layers",
			v1Image: &fakeV1Image{
				errorOnLayers: true,
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotImage, gotErr := FromV1Image(tc.v1Image, DefaultConfig())
			defer func() {
				if gotImage != nil {
					gotImage.CleanUp()
				}
			}()

			if tc.wantErr != (gotErr != nil) {
				t.Errorf("Load(%v) returned error: %v, want error: %v", tc.v1Image, gotErr, tc.wantErr)
			}
		})
	}
}

// ========================================================
// TESTING HELPER METHODS
// ========================================================

// compareChainLayerEntries compares the files in a chain layer to the expected files in the
// chainLayerEntries.
func compareChainLayerEntries(t *testing.T, gotChainLayer image.ChainLayer, wantChainLayerEntries chainLayerEntries, wantErrWhileReadingFiles error) {
	t.Helper()
	chainfs := gotChainLayer.FS()

	for _, filepathContentPair := range wantChainLayerEntries.filepathContentPairs {
		func() {
			gotFile, gotErr := chainfs.Open(filepathContentPair.filepath)
			if wantErrWhileReadingFiles != nil {
				if errors.Is(gotErr, wantErrWhileReadingFiles) {
					return
				}
				t.Fatalf("Open(%v) returned error: %v", filepathContentPair.filepath, gotErr)
			}

			if gotErr != nil {
				t.Fatalf("Open(%v) returned unexpected error: %v", filepathContentPair.filepath, gotErr)
			}

			defer gotFile.Close()

			contentBytes, err := io.ReadAll(gotFile)
			if err != nil {
				t.Fatalf("ReadAll(%v) returned error: %v", filepathContentPair.filepath, err)
			}

			gotContent := string(contentBytes[:])
			if diff := cmp.Diff(gotContent, filepathContentPair.content); diff != "" {
				t.Errorf("Open(%v) returned incorrect content: got \"%s\", want \"%s\"", filepathContentPair.filepath, gotContent, filepathContentPair.content)
			}
		}()
	}
}

func TestInitializeChainLayers(t *testing.T) {
	fakeV1Layer1 := fakev1layer.New("123", "COPY ./foo.txt /foo.txt # buildkit", false, nil)
	fakeV1Layer2 := fakev1layer.New("456", "COPY ./bar.txt /bar.txt # buildkit", false, nil)
	fakeV1Layer3 := fakev1layer.New("789", "COPY ./baz.txt /baz.txt # buildkit", false, nil)

	tests := []struct {
		name            string
		v1Layers        []v1.Layer
		configFile      *v1.ConfigFile
		maxSymlinkDepth int
		want            []*chainLayer
		wantErr         bool
	}{
		{
			name: "nil config file",
			v1Layers: []v1.Layer{
				fakeV1Layer1,
			},
			wantErr: true,
		},
		{
			name: "no config file history entries",
			v1Layers: []v1.Layer{
				fakeV1Layer1,
			},
			configFile: &v1.ConfigFile{
				History: []v1.History{},
			},
			want: []*chainLayer{
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        0,
					latestLayer: &Layer{
						diffID:  "sha256:123",
						v1Layer: fakeV1Layer1,
						isEmpty: false,
					},
				},
			},
		},
		{
			name: "single non-empty layer with history entry",
			v1Layers: []v1.Layer{
				fakeV1Layer1,
			},
			configFile: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "COPY ./foo.txt /foo.txt # buildkit",
					},
				},
			},
			want: []*chainLayer{
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        0,
					latestLayer: &Layer{
						buildCommand: "COPY ./foo.txt /foo.txt # buildkit",
						diffID:       "sha256:123",
						v1Layer:      fakeV1Layer1,
						isEmpty:      false,
					},
				},
			},
		},
		{
			name: "multiple non-empty layer with history entries",
			v1Layers: []v1.Layer{
				fakeV1Layer1,
				fakeV1Layer2,
				fakeV1Layer3,
			},
			configFile: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "COPY ./foo.txt /foo.txt # buildkit",
					},
					{
						CreatedBy: "COPY ./bar.txt /bar.txt # buildkit",
					},
					{
						CreatedBy: "COPY ./baz.txt /baz.txt # buildkit",
					},
				},
			},
			want: []*chainLayer{
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        0,
					latestLayer: &Layer{
						buildCommand: "COPY ./foo.txt /foo.txt # buildkit",
						diffID:       "sha256:123",
						v1Layer:      fakeV1Layer1,
						isEmpty:      false,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        1,
					latestLayer: &Layer{
						buildCommand: "COPY ./bar.txt /bar.txt # buildkit",
						diffID:       "sha256:456",
						v1Layer:      fakeV1Layer2,
						isEmpty:      false,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        2,
					latestLayer: &Layer{
						buildCommand: "COPY ./baz.txt /baz.txt # buildkit",
						diffID:       "sha256:789",
						v1Layer:      fakeV1Layer3,
						isEmpty:      false,
					},
				},
			},
		},
		{
			name: "mix of filled and empty layers with history entries",
			v1Layers: []v1.Layer{
				fakeV1Layer1,
				fakeV1Layer2,
				fakeV1Layer3,
			},
			configFile: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy:  "COPY ./foo.txt /foo.txt # buildkit",
						EmptyLayer: false,
					},
					{
						CreatedBy:  "ENTRYPOINT [\"/bin/sh\"]",
						EmptyLayer: true,
					},
					{
						CreatedBy:  "COPY ./bar.txt /bar.txt # buildkit",
						EmptyLayer: false,
					},
					{
						CreatedBy:  "RANDOM DOCKER COMMAND",
						EmptyLayer: true,
					},
					{
						CreatedBy:  "COPY ./baz.txt /baz.txt # buildkit",
						EmptyLayer: false,
					},
					{
						CreatedBy:  "RUN [\"/bin/sh\"]",
						EmptyLayer: true,
					},
				},
			},
			want: []*chainLayer{
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        0,
					latestLayer: &Layer{
						buildCommand: "COPY ./foo.txt /foo.txt # buildkit",
						diffID:       "sha256:123",
						v1Layer:      fakeV1Layer1,
						isEmpty:      false,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        1,
					latestLayer: &Layer{
						buildCommand: "ENTRYPOINT [\"/bin/sh\"]",
						isEmpty:      true,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        2,
					latestLayer: &Layer{
						buildCommand: "COPY ./bar.txt /bar.txt # buildkit",
						diffID:       "sha256:456",
						v1Layer:      fakeV1Layer2,
						isEmpty:      false,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        3,
					latestLayer: &Layer{
						buildCommand: "RANDOM DOCKER COMMAND",
						isEmpty:      true,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        4,
					latestLayer: &Layer{
						buildCommand: "COPY ./baz.txt /baz.txt # buildkit",
						diffID:       "sha256:789",
						v1Layer:      fakeV1Layer3,
						isEmpty:      false,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        5,
					latestLayer: &Layer{
						buildCommand: "RUN [\"/bin/sh\"]",
						isEmpty:      true,
					},
				},
			},
		},
		{
			name: "more layers than history entries",
			v1Layers: []v1.Layer{
				fakeV1Layer1,
				fakeV1Layer2,
				fakeV1Layer3,
			},
			configFile: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy:  "COPY ./foo.txt /foo.txt # buildkit",
						EmptyLayer: false,
					},
				},
			},
			want: []*chainLayer{
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        0,
					latestLayer: &Layer{
						buildCommand: "COPY ./foo.txt /foo.txt # buildkit",
						diffID:       "sha256:123",
						v1Layer:      fakeV1Layer1,
						isEmpty:      false,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        1,
					latestLayer: &Layer{
						diffID:  "sha256:456",
						v1Layer: fakeV1Layer2,
						isEmpty: false,
					},
				},
				{
					fileNodeTree: pathtree.NewNode[fileNode](),
					index:        2,
					latestLayer: &Layer{
						diffID:  "sha256:789",
						v1Layer: fakeV1Layer3,
						isEmpty: false,
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotChainLayers, err := initializeChainLayers(tc.v1Layers, tc.configFile, tc.maxSymlinkDepth)
			if tc.wantErr {
				if err != nil {
					return
				}
				t.Fatalf("initializeChainLayers(%v, %v, %v) returned nil error, want error", tc.v1Layers, tc.configFile, tc.maxSymlinkDepth)
			}

			if err != nil {
				t.Fatalf("initializeChainLayers(%v, %v, %v) returned an unexpected error: %v", tc.v1Layers, tc.configFile, tc.maxSymlinkDepth, err)
			}

			if diff := cmp.Diff(tc.want, gotChainLayers, cmp.AllowUnexported(chainLayer{}, Layer{}, fakev1layer.FakeV1Layer{}), cmpopts.IgnoreFields(chainLayer{}, "fileNodeTree"), cmpopts.IgnoreFields(Layer{}, "fileNodeTree")); diff != "" {
				t.Fatalf("initializeChainLayers(%v, %v, %v) returned an unexpected diff (-want +got): %v", tc.v1Layers, tc.configFile, tc.maxSymlinkDepth, diff)
			}
		})
	}
}
