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
	"errors"
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
	chainID digest.Digest
	layer   image.Layer
	files   map[string]string
}

// Config is the configuration for creating a FakeChainLayer.
type Config struct {
	TestDir           string
	Index             int
	DiffID            digest.Digest
	ChainID           digest.Digest
	Command           string
	Layer             image.Layer
	Files             map[string]string
	FilesAlreadyExist bool
}

// New creates a new FakeChainLayer.
func New(cfg *Config) (*FakeChainLayer, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	if !cfg.FilesAlreadyExist {
		for name, contents := range cfg.Files {
			filename := filepath.Join(cfg.TestDir, name)
			if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
				return nil, err
			}

			if err := os.WriteFile(filename, []byte(contents), 0600); err != nil {
				return nil, err
			}
		}
	}
	return &FakeChainLayer{
		index:   cfg.Index,
		diffID:  cfg.DiffID,
		chainID: cfg.ChainID,
		command: cfg.Command,
		layer:   cfg.Layer,
		testDir: cfg.TestDir,
		files:   cfg.Files,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// image.ChainLayer implementation
// -------------------------------------------------------------------------------------------------

// Index returns the index of the chain layer.
func (fakeChainLayer *FakeChainLayer) Index() int {
	return fakeChainLayer.index
}

// ChainID returns the chain ID of the chain layer.
func (fakeChainLayer *FakeChainLayer) ChainID() digest.Digest {
	return fakeChainLayer.chainID
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
	return os.Open(filepath.Join(fakeChainLayer.testDir, name))
}

// Stat returns the file info of a file if it exists in the files map.
func (fakeChainLayer *FakeChainLayer) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(path.Join(fakeChainLayer.testDir, name))
}

// ReadDir is not used in the trace package since individual files are opened instead of
// directories.
func (fakeChainLayer *FakeChainLayer) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, errors.New("not implemented")
}
