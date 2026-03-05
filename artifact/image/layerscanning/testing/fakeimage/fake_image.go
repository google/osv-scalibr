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

// Package fakeimage provides a fake implementation of the image.Image interface for testing
// purposes.
package fakeimage

import (
	"github.com/google/osv-scalibr/artifact/image"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// FakeImage is a fake implementation of the image.Image interface for testing purposes.
type FakeImage struct {
	FakeChainLayers []image.ChainLayer
}

// New returns a new FakeImage.
func New(chainLayers []image.ChainLayer) *FakeImage {
	return &FakeImage{
		FakeChainLayers: chainLayers,
	}
}

// Layers returns the layers of the image.
func (i *FakeImage) Layers() ([]image.Layer, error) {
	res := make([]image.Layer, len(i.FakeChainLayers))
	for i, layer := range i.FakeChainLayers {
		res[i] = layer.Layer()
	}
	return res, nil
}

// ChainLayers returns the chain layers of the image.
func (i *FakeImage) ChainLayers() ([]image.ChainLayer, error) {
	return i.FakeChainLayers, nil
}

// FS returns a SCALIBR compliant filesystem that represents the image.
func (i *FakeImage) FS() scalibrfs.FS {
	return i.FakeChainLayers[len(i.FakeChainLayers)-1].FS()
}
