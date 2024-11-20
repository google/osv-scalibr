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
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/osv-scalibr/artifact/image"
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
func TestLoadFrom(t *testing.T) {
	tests := []struct {
		name                  string
		tarPath               string
		config                *Config
		wantChainLayerEntries []chainLayerEntries
		wantErr               error
	}{
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
			wantErr: nil,
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
			wantErr: nil,
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
			wantErr: nil,
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
			wantErr: nil,
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
			wantErr: nil,
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
			wantErr: nil,
		},
		{
			name:    "image with file surpassing max file size",
			tarPath: filepath.Join(testdataDir, "single-file.tar"),
			config: &Config{
				MaxFileBytes: 1,
			},
			wantErr: ErrFileReadLimitExceeded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotImage, gotErr := LoadFrom(tc.tarPath, tc.config)
			defer gotImage.CleanUp()

			if tc.wantErr != nil {
				if errors.Is(gotErr, tc.wantErr) {
					return
				}
				t.Fatalf("Load(%v) returned error: %v, want error: %v", tc.tarPath, gotErr, tc.wantErr)
			}

			if gotErr != nil {
				t.Fatalf("Load(%v) returned unexpected error: %v", tc.tarPath, gotErr)
			}

			chainLayers, err := gotImage.ChainLayers()

			if err != nil {
				t.Fatalf("ChainLayers() returned error: %v", err)
			}

			if len(chainLayers) != len(tc.wantChainLayerEntries) {
				t.Fatalf("ChainLayers() returned incorrect number of chain layers: got %d chain layers, want %d chain layers", len(chainLayers), len(tc.wantChainLayerEntries))
			}

			for i := range chainLayers {
				chainLayer := chainLayers[i]
				wantChainLayerEntries := tc.wantChainLayerEntries[i]

				if wantChainLayerEntries.ignore {
					continue
				}

				compareChainLayerEntries(t, chainLayer, wantChainLayerEntries)
			}

		})
	}
}

// Testing plan:
//  1. Use a fake v1.Image that has no config file. Make sure that Load() returns an error.
//  2. Use a fake v1.Image that returns an error when calling Layers(). Make sure that Load() returns
//     an error.
//  3. Create a real image with a file surpassing the max file size. Make sure that Load() returns
//     an error.
//  4. Devise a pathtree that will return an error when inserting a path. Make sure that Load()
//     returns an error.
func TestLoad(t *testing.T) {
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
			gotImage, gotErr := Load(tc.v1Image, DefaultConfig())
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
func compareChainLayerEntries(t *testing.T, gotChainLayer image.ChainLayer, wantChainLayerEntries chainLayerEntries) {
	t.Helper()

	chainfs := gotChainLayer.FS()

	for _, filepathContentPair := range wantChainLayerEntries.filepathContentPairs {
		gotFile, err := chainfs.Open(filepathContentPair.filepath)
		if err != nil {
			t.Fatalf("Open(%v) returned error: %v", filepathContentPair.filepath, err)
		}
		contentBytes, err := io.ReadAll(gotFile)
		if err != nil {
			t.Fatalf("ReadAll(%v) returned error: %v", filepathContentPair.filepath, err)
		}
		gotContent := string(contentBytes[:])
		if diff := cmp.Diff(gotContent, filepathContentPair.content); diff != "" {
			t.Errorf("Open(%v) returned incorrect content: got %s, want %s", filepathContentPair.filepath, gotContent, filepathContentPair.content)
		}
	}
}
