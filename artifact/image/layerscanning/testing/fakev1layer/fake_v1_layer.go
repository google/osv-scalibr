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
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"testing"

	"archive/tar"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ContentAndMode is a struct that contains the content and mode of a file in a fake v1 layer.
type ContentAndMode struct {
	content string
	mode    fs.FileMode
}

// FakeV1Layer is a fake implementation of the v1.Layer interface for testing purposes.
type FakeV1Layer struct {
	diffID                  string
	buildCommand            string
	isEmpty                 bool
	content                 []byte
	failGettingUncompressed bool
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
	if fakeV1Layer.failGettingUncompressed {
		return nil, errors.New("failed to get uncompressed")
	}
	return io.NopCloser(bytes.NewBuffer(fakeV1Layer.content)), nil
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

// New creates a new FakeV1Layer.
func New(t *testing.T, diffID, buildCommand string, isEmpty bool, files map[string]ContentAndMode, failGettingUncompressed bool) *FakeV1Layer {
	t.Helper()

	var buf bytes.Buffer
	hasher := sha256.New()
	mw := io.MultiWriter(&buf, hasher)
	tarWriter := tar.NewWriter(mw)

	dirWritten := make(map[string]bool)

	// Write all files to tar.
	for name, cm := range files {
		content := cm.content
		mode := int64(cm.mode)

		// Write all directories with more permissions to allow writing folders within directories.
		dir := filepath.Dir(name)
		for dir != "" && dir != "." {
			if err := tarWriter.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Name:     dir,
				Mode:     int64(fs.FileMode(0766)),
			}); err != nil {
				t.Fatalf("tarWriter.WriteHeader: %v", err)
			}

			dirWritten[dir] = true
			dir = filepath.Dir(dir)
		}

		if content == "" {
			if err := tarWriter.WriteHeader(&tar.Header{
				Typeflag: tar.TypeReg,
				Name:     name,
				Size:     0,
				Mode:     mode,
			}); err != nil {
				t.Fatalf("tarWriter.WriteHeader: %v", err)
			}
			continue
		}

		if err := tarWriter.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len([]byte(content))),
			Mode:     mode,
		}); err != nil {
			t.Fatalf("tarWriter.WriteHeader: %v", err)
		}

		if _, err := tarWriter.Write([]byte(content)); err != nil {
			t.Fatalf("tarWriter.Write: %v", err)
		}
	}

	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tarWriter.Close: %v", err)
	}

	return &FakeV1Layer{
		diffID:                  diffID,
		buildCommand:            buildCommand,
		isEmpty:                 isEmpty,
		content:                 buf.Bytes(),
		failGettingUncompressed: failGettingUncompressed,
	}
}
