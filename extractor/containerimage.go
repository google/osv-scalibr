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

package extractor

import "github.com/opencontainers/go-digest"

// ContainerImageMetadata stores metadata about a container image.
type ContainerImageMetadata struct {
	// Index of the container image in the full inventory.
	Index int
	// OSInfo is the key value map from /etc/os-release.
	OSInfo map[string]string
	// LayerMetadata stores metadata about the layers in the container image.
	// Currently this does not store any empty layers.
	LayerMetadata []*LayerMetadata
	// BaseImages stores metadata about the base images that the container image is based on.
	// The first element is always empty.
	BaseImages [][]*BaseImageDetails
}

// LayerMetadata stores metadata about a layer in a container image.
type LayerMetadata struct {
	ParentContainer *ContainerImageMetadata

	// Index of the layer in the ParentContainer image.
	Index   int
	DiffID  digest.Digest
	ChainID digest.Digest
	Command string
	IsEmpty bool
	// Index of the base image match in the ParentContainer image. 0 means no match.
	BaseImageIndex int
}

// BaseImageDetails stores details about a base image.
type BaseImageDetails struct {
	// Repository is the name of the image. (e.g. `debian`, `circleci/node`)
	Repository string
	// Registry is the name of the registry. (e.g. `docker.io`, `ghcr.io`)
	Registry string
	// Plugin name of the plugin used to extract the base image.
	Plugin string
	// ChainID used to query this layer. This is calculated including empty layers, so will not correspond
	// to the ChainID of any layer in the inventory.
	ChainID digest.Digest
}
