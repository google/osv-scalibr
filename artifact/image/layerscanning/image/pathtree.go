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
	"path"
	"strings"

	"github.com/google/osv-scalibr/log"
)

const divider string = "/"

// ErrNodeAlreadyExists is returned when a node already exists at the given path. Given there
// shouldn't be any duplicates to the tree, we should return this error if a node already exists.
var ErrNodeAlreadyExists = errors.New("node already exists")

// RootNode represents the root directory /
type RootNode struct {
	Node            Node
	MaxSymlinkDepth int
}

// Node represents a directory with any number of files
type Node struct {
	virtualFile *virtualFile
	children    map[string]*Node
}

// NewNode creates a new node with the given value.
func NewNode(maxSymlinkDepth int) *RootNode {
	root := &RootNode{
		Node: Node{
			children: make(map[string]*Node),
		},
		MaxSymlinkDepth: maxSymlinkDepth,
	}

	// Initialize the virtual file of the root node.
	if err := root.Insert("/", &virtualFile{virtualPath: "/", mode: fs.ModeDir}); err != nil {
		// This should not happen unless there is a bug with the Insert method.
		log.Warnf("Failed to insert root node: %v", err)
	}
	return root
}

// cleanPath returns a path for use in the tree. An error is returned if path is not formatted as
// expected.
func cleanPath(inputPath string) (string, error) {
	path, found := strings.CutPrefix(inputPath, divider)
	if !found {
		return "", fmt.Errorf("path %q is not an absolute path", inputPath)
	}

	return path, nil
}

// Insert inserts a value into the tree at the given path.
// If a node already exists at the given path, an error is returned.
//
// If a file is inserted without also inserting the parent directory
// the parent directory entry will have a nil value.
func (rootNode *RootNode) Insert(path string, vf *virtualFile) error {
	path, err := cleanPath(path)
	if err != nil {
		return fmt.Errorf("Insert() error: %w", err)
	}

	// If the path is empty, then this is the root node. The value should be set here before splitting
	// the path.
	if path == "" {
		rootNode.Node.virtualFile = vf
		return nil
	}

	cursor := &rootNode.Node
	for _, segment := range strings.Split(path, divider) {
		next, ok := cursor.children[segment]
		// Create the segment if it doesn't exist
		if !ok {
			next = &Node{
				virtualFile: nil,
				children:    make(map[string]*Node),
			}
			cursor.children[segment] = next
		}
		cursor = next
	}

	// If the virtualFile is already set, throw an error.
	if cursor.virtualFile != nil {
		return fmt.Errorf("Insert(%q):%w", divider+path, ErrNodeAlreadyExists)
	}

	cursor.virtualFile = vf
	return nil
}

// getNode returns the node at the given path. This will resolve all intermediate symlinks.
// By setting resolveFinalSymlink, you can choose not to resolve the final symlink,
// so the returned Node could still be a symlink to another Node.
func (rootNode *RootNode) getNode(rawNodePath string, resolveFinalSymlink bool, depth int) (*Node, error) {
	nodePath, err := cleanPath(rawNodePath)
	if err != nil {
		log.Warnf("CleanPath(%q) error: %v", nodePath, err)
		return nil, err
	}

	// If the nodePath is empty, node is the root.
	if nodePath == "" {
		return &rootNode.Node, nil
	}

	if depth > rootNode.MaxSymlinkDepth {
		return nil, ErrSymlinkDepthExceeded
	}

	cursor := &rootNode.Node
	// currentPathIndex can be used to get the parent directory segment including all ancestors
	currentPathIndex := 0
	segments := strings.Split(nodePath, divider)
	for i, segment := range segments {
		next, ok := cursor.children[segment]
		if !ok {
			return nil, fs.ErrNotExist
		}
		cursor = next

		// Skip symlink resolution if this is the last element and we are not resolving the final symlink
		if i == len(segments)-1 && !resolveFinalSymlink {
			break
		}

		// Check if the next cursor is a symlink, if so resolve it before continuing
		if cursor.virtualFile != nil && cursor.virtualFile.targetPath != "" {
			targetPath := cursor.virtualFile.targetPath
			if !path.IsAbs(targetPath) {
				// Join the parent path with the targetPath to get the real path
				targetPath = path.Join(divider+nodePath[:currentPathIndex], targetPath)
			}
			// resolveFinalSymlink should always be true for intermediate resolutions
			cursor, err = rootNode.getNode(targetPath, true, depth+1)
			if err != nil {
				return nil, err
			}
		}

		currentPathIndex += len(segment) + 1
	}

	return cursor, nil
}

// Get retrieves the value at the given path. If no node exists at the given path, nil is returned.
// If there is a symlink node along the path, it's resolved.
// By setting resolveFinalSymlink, if the final node is a symlink, you can choose to resolve the symlink
// until you get a normal file or directory. Or to get the raw symlink virtualFile.
func (rootNode *RootNode) Get(p string, resolveFinalSymlink bool) (*virtualFile, error) {
	pathNode, err := rootNode.getNode(p, resolveFinalSymlink, 0)
	if err != nil {
		return nil, err
	}

	if pathNode.virtualFile == nil {
		return nil, fs.ErrNotExist
	}

	return pathNode.virtualFile, nil
}

// GetChildren retrieves all the direct children of the given path.
func (rootNode *RootNode) GetChildren(path string) ([]*virtualFile, error) {
	pathNode, err := rootNode.getNode(path, true, 0)
	if err != nil {
		return nil, err
	}
	if pathNode == nil {
		// This should not happen, if pathNode is nil, there should be an error
		return nil, nil
	}
	if pathNode.virtualFile == nil || !pathNode.virtualFile.IsDir() {
		return nil, fs.ErrInvalid
	}

	children := []*virtualFile{}
	for _, child := range pathNode.children {
		// Some entries could be nil if a file is inserted without inserting the
		// parent directories.
		if child.virtualFile != nil {
			children = append(children, child.virtualFile)
		}
	}

	return children, nil
}

// Walk walks through all elements of this tree depths first, calling fn at every node.
func (rootNode *RootNode) Walk(fn func(string, *virtualFile) error) error {
	return rootNode.Node.walk("", fn)
}

// walk is a recursive function for walking through the tree and calling fn at every node.
func (node *Node) walk(path string, fn func(string, *virtualFile) error) error {
	// Only call fn if the node has a value.
	if node.virtualFile != nil {
		if err := fn(path, node.virtualFile); err != nil {
			return err
		}
	}
	for key, node := range node.children {
		err := node.walk(path+divider+key, fn)
		if err != nil {
			return err
		}
	}

	return nil
}
