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

// Package terraform extracts modules and providers from Terraform configuration files.
package terraform

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/internal/hclparse"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "misc/terraform"
)

// Extractor extracts Terraform modules and providers.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file extension is '.tf'.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Ext(api.Path()) == ".tf"
}

// Extract extracts packages from Terraform configuration files.
//
// It extracts:
// - Modules with versions from module blocks
// - Providers with versions from terraform.required_providers blocks
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read file: %w", err)
	}

	tree, root, err := hclparse.ParseHCL(ctx, content, input.Path)
	if err != nil {
		return inventory.Inventory{}, err
	}
	defer tree.Close()

	var pkgs []*extractor.Package

	// Walk top-level blocks in the body
	body := hclparse.FindNamedChildByType(root, "body")
	if body == nil {
		return inventory.Inventory{Packages: pkgs}, nil
	}

	for i := range int(body.NamedChildCount()) {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{},
				fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		child := body.NamedChild(i)
		if child == nil {
			continue
		}
		if child.Type() != "block" {
			continue
		}

		blockType := hclparse.GetBlockType(child, content)
		switch blockType {
		case "module":
			if pkg := extractModule(child, content, input.Path); pkg != nil {
				pkgs = append(pkgs, pkg)
			}
		case "terraform":
			providerPkgs := extractProviders(child, content, input.Path)
			pkgs = append(pkgs, providerPkgs...)
		}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// extractModule extracts a package from a module block using tree-sitter AST.
func extractModule(block *sitter.Node, src []byte, location string) *extractor.Package {
	body := hclparse.FindNamedChildByType(block, "body")
	if body == nil {
		return nil
	}

	source, version := hclparse.FindSourceAndVersionValues(body, src)

	// Only extract modules with versions and non-local sources
	if version == "" || source == "" || filepath.IsAbs(source) ||
		strings.HasPrefix(source, ".") || strings.HasPrefix(source, "/") {
		return nil
	}

	return &extractor.Package{
		Name:      source,
		Version:   version,
		PURLType:  purl.TypeTerraform,
		Locations: []string{location},
	}
}

// extractProviders extracts packages from terraform.required_providers blocks.
func extractProviders(terraformBlock *sitter.Node, src []byte, location string) []*extractor.Package {
	var pkgs []*extractor.Package

	body := hclparse.FindNamedChildByType(terraformBlock, "body")
	if body == nil {
		return nil
	}

	// Find required_providers blocks inside the terraform block
	for i := range int(body.NamedChildCount()) {
		child := body.NamedChild(i)
		if child == nil {
			continue
		}
		if child.Type() != "block" || hclparse.GetBlockType(child, src) != "required_providers" {
			continue
		}

		rpBody := hclparse.FindNamedChildByType(child, "body")
		if rpBody == nil {
			continue
		}

		// Each attribute in required_providers is a provider definition
		for j := range int(rpBody.NamedChildCount()) {
			attr := rpBody.NamedChild(j)
			if attr == nil {
				continue
			}
			if attr.Type() != "attribute" {
				continue
			}

			source, version := extractProviderFromAttribute(attr, src)
			if source != "" && version != "" {
				pkgs = append(pkgs, &extractor.Package{
					Name:      source,
					Version:   version,
					PURLType:  purl.TypeTerraform,
					Locations: []string{location},
				})
			}
		}
	}

	return pkgs
}

// extractProviderFromAttribute extracts source and version from a provider attribute
// whose value is an object like { source = "hashicorp/aws", version = "~> 5.92" }.
func extractProviderFromAttribute(attr *sitter.Node, src []byte) (source, version string) {
	// Navigate: expression -> collection_value -> object -> object_elem(s)
	expr := hclparse.FindNamedChildByType(attr, "expression")
	if expr == nil {
		return "", ""
	}

	collVal := hclparse.FindNamedChildByType(expr, "collection_value")
	if collVal == nil {
		return "", ""
	}

	obj := hclparse.FindNamedChildByType(collVal, "object")
	if obj == nil {
		return "", ""
	}

	for i := range int(obj.NamedChildCount()) {
		elem := obj.NamedChild(i)
		if elem == nil {
			continue
		}
		if elem.Type() != "object_elem" {
			continue
		}

		key, val := extractObjectElem(elem, src)
		switch key {
		case "source":
			source = val
		case "version":
			version = val
		}
	}

	return source, version
}

// extractObjectElem extracts the key and value from an object_elem node.
// The key is an identifier inside a variable_expr, and the value is a string literal.
func extractObjectElem(elem *sitter.Node, src []byte) (key, val string) {
	// object_elem has two expression children: key and val
	var expressions []*sitter.Node
	for i := range int(elem.NamedChildCount()) {
		child := elem.NamedChild(i)
		if child != nil && child.Type() == "expression" {
			expressions = append(expressions, child)
		}
	}

	if len(expressions) < 2 {
		return "", ""
	}

	key = hclparse.ExtractIdentifierFromExpr(expressions[0], src)
	val = hclparse.ExtractStringFromExpr(expressions[1], src)
	return key, val
}
