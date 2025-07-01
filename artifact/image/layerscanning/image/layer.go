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

package image

import (
	"errors"
	"fmt"
	"io/fs"
	stdlibpath "path"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/osv-scalibr/artifact/image"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
)

var (
	// ErrSymlinkDepthExceeded is returned when the symlink depth is exceeded.
	ErrSymlinkDepthExceeded = errors.New("symlink depth exceeded")
	// ErrSymlinkCycle is returned when a symlink cycle is found.
	ErrSymlinkCycle = errors.New("symlink cycle found")
)

// ========================================================
// LAYER TYPES AND METHODS
// ========================================================

// Layer implements the Layer interface.
type Layer struct {
	diffID       digest.Digest
	buildCommand string
	isEmpty      bool
	fileNodeTree *RootNode
}

// FS returns a scalibr compliant file system.
func (layer *Layer) FS() scalibrfs.FS {
	return &FS{
		tree: layer.fileNodeTree,
	}
}

// IsEmpty returns whether the layer is empty.
func (layer *Layer) IsEmpty() bool {
	return layer.isEmpty
}

// DiffID returns the diff id of the layer.
func (layer *Layer) DiffID() digest.Digest {
	return layer.diffID
}

// Command returns the layer command of the layer, if available.
func (layer *Layer) Command() string {
	return layer.buildCommand
}

// convertV1Layer converts a v1.Layer to a scalibr Layer. This involves getting the diffID and
// uncompressed tar from the v1.Layer.
func convertV1Layer(v1Layer v1.Layer, command string, isEmpty bool, maxSymlinkDepth int) *Layer {
	var diffID string
	d, err := v1Layer.DiffID()
	if err != nil {
		log.Warnf("failed to get diffID from v1 layer: %v", err)
	} else {
		diffID = d.String()
	}

	return &Layer{
		diffID:       digest.Digest(diffID),
		buildCommand: command,
		isEmpty:      isEmpty,
		fileNodeTree: NewNode(maxSymlinkDepth),
	}
}

// ========================================================
// CHAINLAYER TYPES AND METHODS
// ========================================================

// chainLayer represents all the files on up to a layer (files from a chain of layers).
type chainLayer struct {
	index        int
	chainID      digest.Digest
	fileNodeTree *RootNode
	latestLayer  image.Layer
}

// FS returns a scalibrfs.FS that can be used to scan for inventory.
func (chainLayer *chainLayer) FS() scalibrfs.FS {
	return &FS{
		tree: chainLayer.fileNodeTree,
	}
}

// Index returns the index of the latest layer in the layer chain.
func (chainLayer *chainLayer) Index() int {
	return chainLayer.index
}

func (chainLayer *chainLayer) ChainID() digest.Digest {
	return chainLayer.chainID
}

// Layer returns the latest layer in the layer chain.
func (chainLayer *chainLayer) Layer() image.Layer {
	return chainLayer.latestLayer
}

// ========================================================
// FS TYPES AND METHODS
// ========================================================

// FS implements the scalibrfs.FS interface that will be used when scanning for inventory.
type FS struct {
	tree *RootNode
}

var _ scalibrfs.FS = &FS{}
var _ EvalSymlinksFS = &FS{}

// Open opens a file from the virtual filesystem.
func (chainfs *FS) Open(name string) (fs.File, error) {
	vf, err := chainfs.getVirtualFile(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get virtual file to open %s: %w", name, err)
	}

	return vf, nil
}

// Stat returns a FileInfo object describing the file found at name.
func (chainfs *FS) Stat(name string) (fs.FileInfo, error) {
	vf, err := chainfs.getVirtualFile(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get virtual file to stat %s: %w", name, err)
	}

	return vf.Stat()
}

// ReadDir returns the directory entries found at path name.
func (chainfs *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	vf, err := chainfs.getVirtualFile(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get virtual file to read directory %s: %w", name, err)
	}

	children, err := chainfs.getVirtualFileChildren(vf.virtualPath)
	if err != nil {
		return nil, err
	}

	// dirEntries should be initialized to an empty slice to avoid nil pointer dereference for callers
	// to ReadDir.
	dirEntries := []fs.DirEntry{}
	for _, child := range children {
		if child.isWhiteout {
			continue
		}
		dirEntries = append(dirEntries, child)
	}

	// Sort the directory entries by filename, as is required by the fs.ReadDirFS interface.
	slices.SortFunc(dirEntries, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return dirEntries, nil
}

// EvalSymlink returns the "real" path of a given path.
// This only works for paths where an actual file (symlink or otherwise) actually exists at that location.
func (chainfs *FS) EvalSymlink(path string) (string, error) {
	vf, err := chainfs.getVirtualFile(path)
	if err != nil || vf == nil {
		return "", fmt.Errorf("failed to get virtual file to eval symlink %s: %w", path, err)
	}

	return vf.virtualPath, nil
}

// getVirtualFile returns the virtualFile object for the given path. The virtualFile object stores
// metadata on the virtual file and where it is located on the real filesystem.
func (chainfs *FS) getVirtualFile(path string) (*virtualFile, error) {
	if chainfs.tree == nil {
		return nil, fs.ErrNotExist
	}

	return chainfs.tree.Get(normalizePath(path), true)
}

// getVirtualFileChildren returns the direct virtual file children of the given path. This helper
// function is used to implement the fs.ReadDirFS interface.
func (chainfs *FS) getVirtualFileChildren(path string) ([]*virtualFile, error) {
	if chainfs.tree == nil {
		return nil, fs.ErrNotExist
	}

	return chainfs.tree.GetChildren(normalizePath(path))
}

// ========================================================
// HELPER FUNCTIONS
// ========================================================

// normalizePath normalizes path and makes sure it starts with a slash. SCALIBR starts extraction
// from the "." directory (root), so this is necessary in order to work with the pathtree.
func normalizePath(path string) string {
	if path == "." || path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	path = stdlibpath.Clean(path)

	return path
}

// diffIDForV1Layer returns the diffID of a v1.Layer.
func diffIDForV1Layer(layer v1.Layer) (digest.Digest, error) {
	d, err := layer.DiffID()
	if err != nil {
		return "", fmt.Errorf("failed to get diffID from v1 layer %+v: %w", layer, err)
	}
	diffID, err := digest.Parse(d.String())
	if err != nil {
		return "", fmt.Errorf("failed to parse diffID %q from v1 layer %+v: %w", d.String(), layer, err)
	}
	return diffID, nil
}

// chainIDsForV1Layers returns the chainIDs of a slice of v1.Layers. The chainIDs are computed
// recursively using the identity.ChainIDs function. If an error is encountered when getting the
// diffID of a v1.Layer, the chainIDs computed so far are returned with the error.
// len(v1Layers) == len(chainIDs) is guaranteed even if an error is returned.
func chainIDsForV1Layers(v1Layers []v1.Layer) ([]digest.Digest, error) {
	var diffIDs []digest.Digest
	var err error
	for _, v1Layer := range v1Layers {
		var diffID digest.Digest
		diffID, err = diffIDForV1Layer(v1Layer)
		if err != nil {
			break
		}
		diffIDs = append(diffIDs, diffID)
	}
	chainIDs := make([]digest.Digest, len(v1Layers))
	computedChainIDs := identity.ChainIDs(diffIDs)
	copy(chainIDs, computedChainIDs)
	return chainIDs, err
}
