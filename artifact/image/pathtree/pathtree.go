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

// Package pathtree provides a tree structure for representing file paths.
// Each path segment is a node in the tree, enabling efficient storage
// and retrieval for building virtual file systems.
package pathtree

import (
	"errors"
	"fmt"
	"strings"
)

const divider string = "/"

// ErrNodeAlreadyExists is returned when a node already exists at the given path. Given there
// shouldn't be any duplicates to the tree, we should return this error if a node already exists.
var ErrNodeAlreadyExists = errors.New("node already exists")

// Node root represents the root directory /
type Node[V any] struct {
	value    *V
	children map[string]*Node[V]
}

// NewNode creates a new node with the given value.
func NewNode[V any]() *Node[V] {
	return &Node[V]{
		children: make(map[string]*Node[V]),
	}
}

// Insert inserts a value into the tree at the given path.
// If a node already exists at the given path, an error is returned.
//
// If a file is inserted without also inserting the parent directory
// the parent directory entry will have a nil value.
func (node *Node[V]) Insert(path string, value *V) error {
	path, err := cleanPath(path)
	if err != nil {
		return fmt.Errorf("Insert() error: %w", err)
	}

	// If the path is empty, then this is the root node. The value should be set here before splitting
	// the path.
	if path == "" {
		node.value = value

		return nil
	}

	cursor := node
	for _, segment := range strings.Split(path, divider) {
		next, ok := cursor.children[segment]
		// Create the segment if it doesn't exist
		if !ok {
			next = &Node[V]{
				value:    nil,
				children: make(map[string]*Node[V]),
			}
			cursor.children[segment] = next
		}
		cursor = next
	}

	if cursor.value != nil {
		return fmt.Errorf("Insert(%q):%w", divider+path, ErrNodeAlreadyExists)
	}

	cursor.value = value

	return nil
}

// getNode returns the node at the given path.
func (node *Node[V]) getNode(path string) *Node[V] {
	path, _ = cleanPath(path)

	// If the path is empty, node is the root.
	if path == "" {
		return node
	}

	cursor := node
	for _, segment := range strings.Split(path, divider) {
		next, ok := cursor.children[segment]
		if !ok {
			return nil
		}
		cursor = next
	}

	return cursor
}

// Get retrieves the value at the given path.
// If no node exists at the given path, nil is returned.
func (node *Node[V]) Get(path string) *V {
	pathNode := node.getNode(path)
	if pathNode == nil {
		return nil
	}

	return pathNode.value
}

// GetChildren retrieves all the direct children of the given path.
func (node *Node[V]) GetChildren(path string) []*V {
	pathNode := node.getNode(path)
	if pathNode == nil {
		return nil
	}

	var children = make([]*V, 0, len(pathNode.children))
	for _, child := range pathNode.children {
		// Some entries could be nil if a file is inserted without inserting the
		// parent directories.
		if child.value != nil {
			children = append(children, child.value)
		}
	}

	return children
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

// Walk walks through all elements of this tree depths first, calling fn at every node
func (node *Node[V]) Walk(fn func(string, *V) error) error {
	return node.walk("", fn)
}

// walk is a recursive function for walking through the tree and calling fn at every node.
func (node *Node[V]) walk(path string, fn func(string, *V) error) error {
	// Only call fn if the node has a value.
	if node.value != nil {
		if err := fn(path, node.value); err != nil {
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
