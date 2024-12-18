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

// Package fakelayer provides a fake implementation of the image.Layer interface for testing
// purposes.
package fakelayer

import (
	"fmt"
	"io"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// FakeLayer is a fake implementation of the image.Layer interface for testing purposes.
type FakeLayer struct {
	diffID       string
	buildCommand string
}

// New creates a new FakeLayer.
func New(diffID string, buildCommand string) *FakeLayer {
	return &FakeLayer{
		diffID:       diffID,
		buildCommand: buildCommand,
	}
}

// FS is not currently used for the purposes of layer scanning, thus a nil value is returned.
func (fakeLayer *FakeLayer) FS() scalibrfs.FS {
	return nil
}

// DiffID returns the diffID of the layer.
func (fakeLayer *FakeLayer) DiffID() string {
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
