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

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	// Name is the unique name of this extractor.
	Name = "misc/terraform"
)

// Extractor extracts Terraform modules and providers.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

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

	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(content, input.Path)
	if diags.HasErrors() {
		return inventory.Inventory{}, fmt.Errorf("failed to parse HCL: %w", diags)
	}

	var pkgs []*extractor.Package

	// Extract packages from the parsed file
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return inventory.Inventory{}, fmt.Errorf("unexpected body type")
	}

	for _, block := range body.Blocks {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		switch block.Type {
		case "module":
			if pkg := extractModule(block, input.Path); pkg != nil {
				pkgs = append(pkgs, pkg)
			}
		case "terraform":
			providerPkgs := extractProviders(block, input.Path)
			pkgs = append(pkgs, providerPkgs...)
		}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

func extractModule(block *hclsyntax.Block, location string) *extractor.Package {
	var source, version string

	for _, attr := range block.Body.Attributes {
		switch attr.Name {
		case "source":
			if val, diags := attr.Expr.Value(nil); !diags.HasErrors() && val.Type() == cty.String {
				source = val.AsString()
			}
		case "version":
			if val, diags := attr.Expr.Value(nil); !diags.HasErrors() && val.Type() == cty.String {
				version = val.AsString()
			}
		}
	}

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

func extractProviders(terraformBlock *hclsyntax.Block, location string) []*extractor.Package {
	var pkgs []*extractor.Package

	for _, block := range terraformBlock.Body.Blocks {
		if block.Type != "required_providers" {
			continue
		}

		for _, attr := range block.Body.Attributes {
			// The attribute value should be an object with source and optionally version
			val, diags := attr.Expr.Value(nil)
			if diags.HasErrors() || !val.Type().IsObjectType() {
				continue
			}

			var source, version string
			valMap := val.AsValueMap()

			if sourceVal, ok := valMap["source"]; ok && sourceVal.Type() == cty.String {
				source = sourceVal.AsString()
			}
			if versionVal, ok := valMap["version"]; ok && versionVal.Type() == cty.String {
				version = versionVal.AsString()
			}

			// Only extract providers with both source and version
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
