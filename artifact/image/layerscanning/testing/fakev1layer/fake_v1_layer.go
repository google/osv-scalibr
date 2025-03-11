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

// Package fakev1layer provides a fake implementation of the v1.Layer interface for testing
// purposes.
package fakev1layer

import (
	"errors"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// FakeV1Layer is a fake implementation of the v1.Layer interface for testing purposes.
type FakeV1Layer struct {
	diffID       string
	buildCommand string
	isEmpty      bool
	uncompressed io.ReadCloser
}

// New creates a new FakeV1Layer.
func New(diffID string, buildCommand string, isEmpty bool, uncompressed io.ReadCloser) *FakeV1Layer {
	return &FakeV1Layer{
		diffID:       diffID,
		buildCommand: buildCommand,
		isEmpty:      isEmpty,
		uncompressed: uncompressed,
	}
}

// DiffID returns the diffID of the layer.
func (fakeV1Layer *FakeV1Layer) DiffID() (v1.Hash, error) {
	if fakeV1Layer.diffID == "" {
		return v1.Hash{}, errors.New("diffID is empty")
	}
	return v1.Hash{
		Algorithm: "sha256",
		Hex:       fakeV1Layer.diffID,
	}, nil
}

// Digest is not used for the purposes of layer scanning, thus an empty hash is returned.
func (fakeV1Layer *FakeV1Layer) Digest() (v1.Hash, error) {
	return v1.Hash{}, nil
}

// Uncompressed returns the uncompressed tar reader.
func (fakeV1Layer *FakeV1Layer) Uncompressed() (io.ReadCloser, error) {
	return fakeV1Layer.uncompressed, nil
}

// Compressed is not used for the purposes of layer scanning, thus a nil value is returned.
func (fakeV1Layer *FakeV1Layer) Compressed() (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

// Size is not used for the purposes of layer scanning, thus a zero value is returned.
func (fakeV1Layer *FakeV1Layer) Size() (int64, error) {
	return 0, errors.New("not implemented")
}

// MediaType returns a fake media type.
func (fakeV1Layer *FakeV1Layer) MediaType() (types.MediaType, error) {
	return "fake layer", nil
}
