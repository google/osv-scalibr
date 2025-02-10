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
	"io"
	"io/fs"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/pathtree"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/opencontainers/go-digest"
)

var (
	// ErrDiffIDMissingFromLayer is returned when the diffID is missing from a v1 layer.
	ErrDiffIDMissingFromLayer = errors.New("failed to get diffID from v1 layer")
	// ErrUncompressedReaderMissingFromLayer is returned when the uncompressed reader is missing from a v1 layer.
	ErrUncompressedReaderMissingFromLayer = errors.New("failed to get uncompressed reader from v1 layer")
	// ErrSymlinkDepthExceeded is returned when the symlink depth is exceeded.
	ErrSymlinkDepthExceeded = errors.New("symlink depth exceeded")
	// ErrSymlinkCycle is returned when a symlink cycle is found.
	ErrSymlinkCycle = errors.New("symlink cycle found")

	// DefaultMaxSymlinkDepth is the default maximum symlink depth.
	DefaultMaxSymlinkDepth = 6
)

// ========================================================
// LAYER TYPES AND METHODS
// ========================================================

// Layer implements the Layer interface.
type Layer struct {
	v1Layer      v1.Layer
	diffID       digest.Digest
	buildCommand string
	isEmpty      bool
}

// FS returns a scalibr compliant file system.
func (layer *Layer) FS() scalibrfs.FS {
	return nil
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

// Uncompressed returns a new uncompressed ReadCloser from the v1 layer which holds all files in the
// layer.
// TODO: b/378938357 - Figure out a better way to get the uncompressed ReadCloser.
func (layer *Layer) Uncompressed() (io.ReadCloser, error) {
	uncompressed, err := layer.v1Layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUncompressedReaderMissingFromLayer, err)
	}
	return uncompressed, nil
}

// convertV1Layer converts a v1.Layer to a scalibr Layer. This involves getting the diffID and
// uncompressed tar from the v1.Layer.
func convertV1Layer(v1Layer v1.Layer, command string, isEmpty bool) (*Layer, error) {
	diffID, err := v1Layer.DiffID()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiffIDMissingFromLayer, err)
	}

	return &Layer{
		v1Layer:      v1Layer,
		diffID:       digest.Digest(diffID.String()),
		buildCommand: command,
		isEmpty:      isEmpty,
	}, nil
}

// ========================================================
// CHAINLAYER TYPES AND METHODS
// ========================================================

// chainLayer represents all the files on up to a layer (files from a chain of layers).
type chainLayer struct {
	index        int
	fileNodeTree *pathtree.Node[fileNode]
	latestLayer  image.Layer
}

// FS returns a scalibrfs.FS that can be used to scan for inventory.
func (chainLayer *chainLayer) FS() scalibrfs.FS {
	return &FS{
		tree:            chainLayer.fileNodeTree,
		maxSymlinkDepth: DefaultMaxSymlinkDepth,
	}
}

// Index returns the index of the latest layer in the layer chain.
func (chainLayer *chainLayer) Index() int {
	return chainLayer.index
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
	tree            *pathtree.Node[fileNode]
	maxSymlinkDepth int
}

// resolveSymlink resolves a symlink by following the target path. It returns the resolved file
// node or an error if the symlink depth is exceeded or a cycle is found. An ErrSymlinkDepthExceeded
// error if the symlink depth is exceeded or an ErrSymlinkCycle error if a cycle is
// found. Whichever error is encountered first is returned. The cycle detection leverages Floyd's
// tortoise and hare algorithm, which utilizes a slow and fast pointer.
func (chainfs FS) resolveSymlink(node *fileNode, depth int) (*fileNode, error) {
	// slowNode is used to keep track of the slow moving node.
	slowNode := node
	advanceSlowNode := false
	initialSymlinkPath := node.virtualPath

	var err error
	for {
		if depth < 0 {
			return nil, ErrSymlinkDepthExceeded
		}

		isSymlink := node.mode&fs.ModeSymlink != 0
		if !isSymlink {
			return node, nil
		}

		// Move on to the next fileNode.
		node, err = chainfs.getFileNode(node.targetPath)
		if err != nil {
			return nil, err
		}

		// If the slowNode is the same as the current node, then a cycle is found since the node caught
		// up to the slowNode.
		if node == slowNode {
			return nil, fmt.Errorf("%w, initial symlink: %s", ErrSymlinkCycle, initialSymlinkPath)
		}

		if advanceSlowNode {
			slowNode, err = chainfs.getFileNode(slowNode.targetPath)
			if err != nil {
				return nil, err
			}
		}

		advanceSlowNode = !advanceSlowNode
		depth--
	}
}

// Open opens a file from the virtual filesystem.
func (chainfs FS) Open(name string) (fs.File, error) {
	fileNode, err := chainfs.getFileNode(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get file node to open %s: %w", name, err)
	}

	resolvedNode, err := chainfs.resolveSymlink(fileNode, chainfs.maxSymlinkDepth)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve symlink for file node %s: %w", fileNode.virtualPath, err)
	}
	return resolvedNode, nil
}

// Stat returns a FileInfo object describing the file found at name.
func (chainfs *FS) Stat(name string) (fs.FileInfo, error) {
	node, err := chainfs.getFileNode(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get file node to stat %s: %w", name, err)
	}

	resolvedNode, err := chainfs.resolveSymlink(node, chainfs.maxSymlinkDepth)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve symlink for file node %s: %w", node.virtualPath, err)
	}
	return resolvedNode.Stat()
}

// ReadDir returns the directory entries found at path name.
func (chainfs *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	node, err := chainfs.getFileNode(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get file node to read directory %s: %w", name, err)
	}

	resolvedNode, err := chainfs.resolveSymlink(node, chainfs.maxSymlinkDepth)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve symlink for file node %s: %w", node.virtualPath, err)
	}

	children, err := chainfs.getFileNodeChildren(resolvedNode.virtualPath)
	if err != nil {
		return nil, err
	}

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

// getFileNode returns the fileNode object for the given path. The filenode stores metadata on the
// virtual file and where it is located on the real filesystem.
func (chainfs *FS) getFileNode(path string) (*fileNode, error) {
	if chainfs.tree == nil {
		return nil, fs.ErrNotExist
	}

	node := chainfs.tree.Get(normalizePath(path))
	if node == nil {
		return nil, fs.ErrNotExist
	}
	return node, nil
}

func (chainfs *FS) getFileNodeChildren(path string) ([]*fileNode, error) {
	if chainfs.tree == nil {
		return nil, fs.ErrNotExist
	}

	children := chainfs.tree.GetChildren(normalizePath(path))
	if children == nil {
		return nil, fs.ErrNotExist
	}
	return children, nil
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
	return path
}
