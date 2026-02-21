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
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/hcl"
)

// ParseHCL parses HCL content using tree-sitter and returns the root node.
// The caller must call tree.Close() when done.
func ParseHCL(ctx context.Context, content []byte, path string) (*sitter.Tree, *sitter.Node, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(hcl.GetLanguage())

	tree, err := parser.ParseCtx(ctx, nil, content)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse HCL: %w", err)
	}

	root := tree.RootNode()
	if root != nil && root.HasError() {
		tree.Close()
		return nil, nil, fmt.Errorf("failed to parse HCL: syntax errors in %s", path)
	}

	return tree, root, nil
}

// FindNamedChildByType returns the first named child of the given type, or nil.
func FindNamedChildByType(node *sitter.Node, childType string) *sitter.Node {
	for i := range int(node.NamedChildCount()) {
		child := node.NamedChild(i)
		if child != nil && child.Type() == childType {
			return child
		}
	}
	return nil
}

// NodeText returns the text content of a node.
func NodeText(node *sitter.Node, src []byte) string {
	return string(src[node.StartByte():node.EndByte()])
}

// GetBlockType returns the type identifier of a block node (e.g. "module", "terraform", "provider").
func GetBlockType(block *sitter.Node, src []byte) string {
	for i := range int(block.NamedChildCount()) {
		child := block.NamedChild(i)
		if child != nil && child.Type() == "identifier" {
			return NodeText(child, src)
		}
	}
	return ""
}

// GetBlockLabel returns the first string label of a block node (e.g. the provider address).
func GetBlockLabel(block *sitter.Node, src []byte) string {
	for i := range int(block.NamedChildCount()) {
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
func ExtractStringFromExpr(expr *sitter.Node, src []byte) string {
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
func ExtractAttribute(attr *sitter.Node, src []byte) (key, val string) {
	for i := range int(attr.NamedChildCount()) {
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
func FindSourceAndVersionValues(body *sitter.Node, src []byte) (source, version string) {
	for i := range int(body.NamedChildCount()) {
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
func ExtractIdentifierFromExpr(expr *sitter.Node, src []byte) string {
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
