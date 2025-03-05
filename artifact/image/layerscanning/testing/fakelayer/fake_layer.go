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

// Package fakelayer provides a fake implementation of the image.Layer interface for testing
// purposes.
package fakelayer

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/opencontainers/go-digest"
)

// FakeLayer is a fake implementation of the image.Layer interface for testing purposes.
type FakeLayer struct {
	testDir      string
	diffID       digest.Digest
	buildCommand string
	files        map[string]string
}

// New creates a new FakeLayer.
func New(testDir string, diffID digest.Digest, buildCommand string, files map[string]string, filesAlreadyExist bool) (*FakeLayer, error) {
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

	return &FakeLayer{
		testDir:      testDir,
		diffID:       diffID,
		buildCommand: buildCommand,
		files:        files,
	}, nil
}

// FS is not currently used for the purposes of layer scanning, thus a nil value is returned.
func (fakeLayer *FakeLayer) FS() scalibrfs.FS {
	return fakeLayer
}

// DiffID returns the diffID of the layer.
func (fakeLayer *FakeLayer) DiffID() digest.Digest {
	return fakeLayer.diffID
}

// Command returns the command of the layer.
func (fakeLayer *FakeLayer) Command() string {
	return fakeLayer.buildCommand
}

// IsEmpty returns false for the purposes of layer scanning.
func (fakeLayer *FakeLayer) IsEmpty() bool {
	return false
}

// Uncompressed is not used for the purposes of layer scanning, thus a nil value is returned.
func (fakeLayer *FakeLayer) Uncompressed() (io.ReadCloser, error) {
	return nil, fmt.Errorf("not implemented")
}

// -------------------------------------------------------------------------------------------------
// scalibrfs.FS implementation
// -------------------------------------------------------------------------------------------------

// Open returns a file if it exists in the files map.
func (fakeLayer *FakeLayer) Open(name string) (fs.File, error) {
	if _, ok := fakeLayer.files[name]; ok {
		filename := filepath.Join(fakeLayer.testDir, name)

		return os.Open(filename)
	}

	return nil, os.ErrNotExist
}

// Stat returns the file info of a file if it exists in the files map.
func (fakeLayer *FakeLayer) Stat(name string) (fs.FileInfo, error) {
	if _, ok := fakeLayer.files[name]; ok {
		return os.Stat(path.Join(fakeLayer.testDir, name))
	}

	return nil, os.ErrNotExist
}

// ReadDir is not used in the trace package since individual files are opened instead of
// directories.
func (fakeLayer *FakeLayer) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, fmt.Errorf("not implemented")
}
