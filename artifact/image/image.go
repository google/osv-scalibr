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

// Package image provides functionality to scan a container image by layers for software
// inventory.
package image

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/osv-scalibr/artifact/image/require"
	"github.com/google/osv-scalibr/artifact/image/unpack"
	"github.com/opencontainers/go-digest"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// Layer is a filesystem derived from a container layer that can be scanned for software inventory.
// It also holds metadata about the container layer such as whether it is empty, its diffID, index,
// and command.
type Layer interface {
	// FS outputs a filesystem that consist of the files found in the layer. This includes files that
	// were added or modified. Whiteout files are also included in the filesystem if files or
	// directories from previous layers were removed.
	FS() scalibrfs.FS
	// IsEmpty signifies whether the layer is empty. This should correspond with an empty filesystem
	// produced by the FS method.
	IsEmpty() bool
	// DiffID is the hash of the uncompressed layer. Will be an empty string if the layer is empty.
	DiffID() digest.Digest
	// Command is the specific command that produced the layer.
	Command() string
}

// ChainLayer is a filesystem derived from container layers that can be scanned for software
// inventory. It holds all the files found in layer 0, layer 1, ..., layer n (where n is the layer
// index). It also holds metadata about the latest container layer such as whether it is empty, its
// diffID, command, and index.
type ChainLayer interface {
	// FS output an filesystem that consist of the files found in the layer n and all previous layers
	// (layer 0, layer 1, ..., layer n).
	FS() scalibrfs.FS
	// Index is the index of the latest layer in the layer chain.
	Index() int
	// ChainID is the layer chain ID (sha256 hash) of the layer in the container image.
	// https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
	ChainID() digest.Digest
	// Layer is the latest layer in the layer chain.
	Layer() Layer
}

// Image is a container image that can be scanned for software inventory. It is composed of a set of
// layers that can be scanned for software inventory.
type Image interface {
	// Layers returns the layers of the image.
	Layers() ([]Layer, error)
	// ChainLayers returns the chain layers of the image.
	ChainLayers() ([]ChainLayer, error)
	// FS returns a SCALIBR compliant filesystem that represents the image.
	FS() scalibrfs.FS
}

// V1ImageFromRemoteName creates a v1.Image from a remote container image name.
func V1ImageFromRemoteName(imageName string, imageOptions ...remote.Option) (v1.Image, error) {
	imageName = strings.TrimPrefix(imageName, "https://")
	var image v1.Image
	if strings.Contains(imageName, "@") {
		// Pull from a digest name.
		ref, err := name.NewDigest(strings.TrimPrefix(imageName, "https://"))
		if err != nil {
			return nil, fmt.Errorf("unable to parse digest: %w", err)
		}
		descriptor, err := remote.Get(ref, imageOptions...)
		if err != nil {
			return nil, fmt.Errorf("couldn’t pull remote image %s: %w", ref, err)
		}
		image, err = descriptor.Image()
		if err != nil {
			return nil, fmt.Errorf("couldn’t parse image manifest %s: %w", ref, err)
		}
	} else {
		// Pull from a tag.
		tag, err := name.NewTag(strings.TrimPrefix(imageName, "https://"))
		if err != nil {
			return nil, fmt.Errorf("unable to parse image reference: %w", err)
		}
		image, err = remote.Image(tag, imageOptions...)
		if err != nil {
			return nil, fmt.Errorf("couldn’t pull remote image %s: %w", tag, err)
		}
	}
	return image, nil
}

// NewFromRemoteName pulls a remote container and creates a
// SCALIBR filesystem for scanning it.
func NewFromRemoteName(imageName string, imageOptions ...remote.Option) (scalibrfs.FS, error) {
	image, err := V1ImageFromRemoteName(imageName, imageOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to load image from remote name %q: %w", imageName, err)
	}
	return NewFromImage(image)
}

// NewFromImage creates a SCALIBR filesystem for scanning a container
// from its image descriptor.
func NewFromImage(image v1.Image) (scalibrfs.FS, error) {
	outDir, err := os.MkdirTemp(os.TempDir(), "scalibr-container-")
	if err != nil {
		return nil, fmt.Errorf("couldn’t create tmp dir for image: %w", err)
	}
	// Squash the image's final layer into a directory.
	cfg := &unpack.UnpackerConfig{
		SymlinkResolution:  unpack.SymlinkRetain,
		SymlinkErrStrategy: unpack.SymlinkErrLog,
		MaxPass:            unpack.DefaultMaxPass,
		MaxFileBytes:       unpack.DefaultMaxFileBytes,
		Requirer:           &require.FileRequirerAll{},
	}
	unpacker, err := unpack.NewUnpacker(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create image unpacker: %w", err)
	}
	if err = unpacker.UnpackSquashed(outDir, image); err != nil {
		return nil, fmt.Errorf("failed to unpack image into directory %q: %w", outDir, err)
	}
	return scalibrfs.DirFS(outDir), nil
}
