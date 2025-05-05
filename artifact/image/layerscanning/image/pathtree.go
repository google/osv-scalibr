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
	"strings"
)

const divider string = "/"

// ErrNodeAlreadyExists is returned when a node already exists at the given path. Given there
// shouldn't be any duplicates to the tree, we should return this error if a node already exists.
var ErrNodeAlreadyExists = errors.New("node already exists")

// Node root represents the root directory /
type Node struct {
	virtualFile *virtualFile
	children    map[string]*Node
}

// NewNode creates a new node with the given value.
func NewNode() *Node {
	return &Node{
		children: make(map[string]*Node),
	}
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
func (node *Node) Insert(path string, vf *virtualFile) error {
	path, err := cleanPath(path)
	if err != nil {
		return fmt.Errorf("Insert() error: %w", err)
	}

	// If the path is empty, then this is the root node. The value should be set here before splitting
	// the path.
	if path == "" {
		node.virtualFile = vf
		return nil
	}

	cursor := node
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

// isSymlinkNode returns true if the node contains a valid virtual file that represents a symlink.
func isSymlinkNode(node *Node) bool {
	return node.virtualFile != nil && node.virtualFile.mode&fs.ModeSymlink != 0
}

// getFirstSymlinkNode returns the first symlink node it encounters while going down the tree. This
// function is used in order to handle symlinked directories.
func (node *Node) getFirstSymlinkNode(nodePath string) *Node {
	nodePath, _ = cleanPath(nodePath)

	// If the nodePath is empty, node is the root.
	if nodePath == "" {
		return node
	}

	if isSymlinkNode(node) {
		return node
	}

	cursor := node
	for _, segment := range strings.Split(nodePath, divider) {
		next, ok := cursor.children[segment]
		if !ok {
			return nil
		}
		if isSymlinkNode(next) {
			return next
		}
		cursor = next
	}
	return cursor
}

// getNode returns the node at the given path.
func (node *Node) getNode(nodePath string) *Node {
	nodePath, _ = cleanPath(nodePath)

	// If the nodePath is empty, node is the root.
	if nodePath == "" {
		return node
	}

	cursor := node
	for _, segment := range strings.Split(nodePath, divider) {
		next, ok := cursor.children[segment]
		if !ok {
			return nil
		}
		cursor = next
	}
	return cursor
}

// Get retrieves the value at the given path. If no node exists at the given path, nil is returned.
// If there is a symlink node along the path, then a symlink directory has been found. In order to
// resolve it, we follow the symlink and
func (node *Node) Get(p string) *virtualFile {
	if pathNode := node.getNode(p); pathNode != nil {
		return pathNode.virtualFile
	}

	symlinkNode := node.getFirstSymlinkNode(p)
	if symlinkNode == nil || symlinkNode.virtualFile == nil {
		return nil
	}

	targetPath := strings.Replace(p, symlinkNode.virtualFile.virtualPath, symlinkNode.virtualFile.targetPath, 1)
	if targetNode := node.getNode(targetPath); targetNode != nil {
		return targetNode.virtualFile
	}

	return nil
}

// GetChildren retrieves all the direct children of the given path.
func (node *Node) GetChildren(path string) []*virtualFile {
	pathNode := node.getNode(path)
	if pathNode == nil {
		return nil
	}

	children := []*virtualFile{}
	for _, child := range pathNode.children {
		// Some entries could be nil if a file is inserted without inserting the
		// parent directories.
		if child.virtualFile != nil {
			children = append(children, child.virtualFile)
		}
	}

	return children
}

// Walk walks through all elements of this tree depths first, calling fn at every node.
func (node *Node) Walk(fn func(string, *virtualFile) error) error {
	return node.walk("", fn)
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
