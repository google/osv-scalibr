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

// Package fakechainlayer provides a fake implementation of the image.ChainLayer and scalibrfs.FS
// interface for testing purposes.
package fakechainlayer

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/google/osv-scalibr/artifact/image"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/opencontainers/go-digest"
)

// FakeChainLayer is a fake implementation of the image.ChainLayer and scalibrfs.FS interface for
// testing purposes.
type FakeChainLayer struct {
	index   int
	command string
	testDir string
	diffID  digest.Digest
	layer   image.Layer
	files   map[string]string
}

// New creates a new FakeChainLayer.
func New(testDir string, index int, diffID digest.Digest, command string, layer image.Layer, files map[string]string, filesAlreadyExist bool) (*FakeChainLayer, error) {
	if !filesAlreadyExist {
		for name, contents := range files {
			filename := filepath.Join(testDir, name)
			if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
				return nil, err
			}

			if err := os.WriteFile(filename, []byte(contents), 0600); err != nil {
				return nil, err
			}
		}
	}
	return &FakeChainLayer{
		index:   index,
		diffID:  diffID,
		command: command,
		layer:   layer,
		testDir: testDir,
		files:   files,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// image.ChainLayer implementation
// -------------------------------------------------------------------------------------------------

// Index returns the index of the chain layer.
func (fakeChainLayer *FakeChainLayer) Index() int {
	return fakeChainLayer.index
}

// Layer returns the underlying layer of the chain layer.
func (fakeChainLayer *FakeChainLayer) Layer() image.Layer {
	return fakeChainLayer.layer
}

// FS returns a scalibrfs.FS that can be used to scan for inventory. fakeChainLayer is a
// scalibrfs.FS, thus this method returns itself.
func (fakeChainLayer *FakeChainLayer) FS() scalibrfs.FS {
	return fakeChainLayer
}

// -------------------------------------------------------------------------------------------------
// scalibrfs.FS implementation
// -------------------------------------------------------------------------------------------------

// Open returns a file if it exists in the files map.
func (fakeChainLayer *FakeChainLayer) Open(name string) (fs.File, error) {
	if _, ok := fakeChainLayer.files[name]; ok {
		filename := filepath.Join(fakeChainLayer.testDir, name)
		return os.Open(filename)
	}
	return nil, os.ErrNotExist
}

// Stat returns the file info of a file if it exists in the files map.
func (fakeChainLayer *FakeChainLayer) Stat(name string) (fs.FileInfo, error) {
	if _, ok := fakeChainLayer.files[name]; ok {
		return os.Stat(path.Join(fakeChainLayer.testDir, name))
	}
	return nil, os.ErrNotExist
}

// ReadDir is not used in the trace package since individual files are opened instead of
// directories.
func (fakeChainLayer *FakeChainLayer) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, fmt.Errorf("not implemented")
}
