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

// Package hclparse provides shared tree-sitter based HCL parsing utilities
// for Terraform extractors.
package hclparse

import (
	"fmt"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// Tree wraps a gotreesitter.Tree and provides a Close method for cleanup.
type Tree struct {
	inner *gotreesitter.Tree
}

// Close releases the tree resources.
func (t *Tree) Close() {
	if t.inner != nil {
		t.inner.Release()
	}
}

// Node wraps a gotreesitter node and provides tree-sitter-like accessors.
type Node struct {
	inner *gotreesitter.Node
	lang  *gotreesitter.Language
}

// Type returns the node's type name (e.g. "body", "block", "identifier").
func (n *Node) Type() string {
	if n == nil || n.inner == nil {
		return ""
	}
	return n.inner.Type(n.lang)
}

// NamedChildCount returns the number of named children.
func (n *Node) NamedChildCount() int {
	if n == nil || n.inner == nil {
		return 0
	}
	return n.inner.NamedChildCount()
}

// NamedChild returns the i-th named child, or nil.
func (n *Node) NamedChild(i int) *Node {
	if n == nil || n.inner == nil {
		return nil
	}
	child := n.inner.NamedChild(i)
	if child == nil {
		return nil
	}
	return &Node{inner: child, lang: n.lang}
}

// HasError returns true if the node or any descendant has a parse error.
func (n *Node) HasError() bool {
	if n == nil || n.inner == nil {
		return false
	}
	return n.inner.HasError()
}

// StartByte returns the byte offset where this node starts.
func (n *Node) StartByte() uint32 {
	if n == nil || n.inner == nil {
		return 0
	}
	return n.inner.StartByte()
}

// EndByte returns the byte offset where this node ends.
func (n *Node) EndByte() uint32 {
	if n == nil || n.inner == nil {
		return 0
	}
	return n.inner.EndByte()
}

// Text returns the source text covered by this node.
func (n *Node) Text(src []byte) string {
	if n == nil || n.inner == nil {
		return ""
	}
	return n.inner.Text(src)
}

// ParseHCL parses HCL content using gotreesitter and returns the tree and root node.
// The caller must call tree.Close() when done.
// The first parameter is accepted for API compatibility but unused.
func ParseHCL(_ any, content []byte, path string) (*Tree, *Node, error) {
	lang := grammars.HclLanguage()
	parser := gotreesitter.NewParser(lang)

	tree, err := parser.Parse(content)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse HCL: %w", err)
	}

	root := tree.RootNode()
	if root != nil && root.HasError() {
		tree.Release()
		return nil, nil, fmt.Errorf("failed to parse HCL: syntax errors in %s", path)
	}

	return &Tree{inner: tree}, &Node{inner: root, lang: lang}, nil
}

// FindNamedChildByType returns the first named child of the given type, or nil.
func FindNamedChildByType(node *Node, childType string) *Node {
	if node == nil {
		return nil
	}
	for i := range node.NamedChildCount() {
		child := node.NamedChild(i)
		if child != nil && child.Type() == childType {
			return child
		}
	}
	return nil
}

// NodeText returns the text content of a node.
func NodeText(node *Node, src []byte) string {
	if node == nil {
		return ""
	}
	return string(src[node.StartByte():node.EndByte()])
}

// GetBlockType returns the type identifier of a block node (e.g. "module", "terraform", "provider").
func GetBlockType(block *Node, src []byte) string {
	for i := range block.NamedChildCount() {
		child := block.NamedChild(i)
		if child != nil && child.Type() == "identifier" {
			return NodeText(child, src)
		}
	}
	return ""
}

// GetBlockLabel returns the first string label of a block node (e.g. the provider address).
func GetBlockLabel(block *Node, src []byte) string {
	for i := range block.NamedChildCount() {
		child := block.NamedChild(i)
		if child != nil && child.Type() == "string_lit" {
			tmplLit := FindNamedChildByType(child, "template_literal")
			if tmplLit != nil {
				return NodeText(tmplLit, src)
			}
		}
	}
	return ""
}

// ExtractStringFromExpr extracts the unquoted string value from an expression node.
// It navigates: expression -> literal_value -> string_lit -> template_literal.
func ExtractStringFromExpr(expr *Node, src []byte) string {
	litVal := FindNamedChildByType(expr, "literal_value")
	if litVal == nil {
		return ""
	}
	strLit := FindNamedChildByType(litVal, "string_lit")
	if strLit == nil {
		return ""
	}
	tmplLit := FindNamedChildByType(strLit, "template_literal")
	if tmplLit == nil {
		return ""
	}
	return NodeText(tmplLit, src)
}

// ExtractAttribute extracts the key name and string value from an attribute node.
func ExtractAttribute(attr *Node, src []byte) (key, val string) {
	for i := range attr.NamedChildCount() {
		child := attr.NamedChild(i)
		if child == nil {
			continue
		}
		switch child.Type() {
		case "identifier":
			key = NodeText(child, src)
		case "expression":
			val = ExtractStringFromExpr(child, src)
		}
	}
	return key, val
}

// FindSourceAndVersionValues walks the body node and extracts "source" and "version" attribute values.
func FindSourceAndVersionValues(body *Node, src []byte) (source, version string) {
	for i := range body.NamedChildCount() {
		child := body.NamedChild(i)
		if child == nil {
			continue
		}
		if child.Type() != "attribute" {
			continue
		}

		key, val := ExtractAttribute(child, src)
		switch key {
		case "source":
			source = val
		case "version":
			version = val
		}
	}
	return source, version
}

// ExtractIdentifierFromExpr extracts an identifier from an expression node.
// It navigates: expression -> variable_expr -> identifier.
func ExtractIdentifierFromExpr(expr *Node, src []byte) string {
	varExpr := FindNamedChildByType(expr, "variable_expr")
	if varExpr == nil {
		return ""
	}
	ident := FindNamedChildByType(varExpr, "identifier")
	if ident == nil {
		return ""
	}
	return NodeText(ident, src)
}
