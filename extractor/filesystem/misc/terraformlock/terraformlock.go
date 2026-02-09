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

// Package terraformlock extracts Terraform provider names and versions from .terraform.lock.hcl files.
package terraformlock

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

const (
	// Name is the unique name of this extractor.
	Name = "misc/terraformlock"
)

// Extractor extracts Terraform providers from .terraform.lock.hcl files.
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

// FileRequired returns true if the file name is '.terraform.lock.hcl'.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == ".terraform.lock.hcl"
}

// Extract extracts packages from the .terraform.lock.hcl file.
//
// Reference: https://developer.hashicorp.com/terraform/language/files/dependency-lock
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read file: %w", err)
	}

	file, diags := hclsyntax.ParseConfig(content, input.Path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return inventory.Inventory{}, fmt.Errorf("failed to parse HCL: %w", diags)
	}

	var pkgs []*extractor.Package

	// Iterate through the body blocks to find provider blocks
	for _, block := range file.Body.(*hclsyntax.Body).Blocks {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		if block.Type != "provider" {
			continue
		}

		// The provider block has a label which is the provider address
		if len(block.Labels) == 0 {
			continue
		}

		providerAddress := block.Labels[0]
		// Extract version from the block attributes
		version := ""
		for _, attr := range block.Body.Attributes {
			if attr.Name == "version" {
				// Try to extract the version value
				val, diags := attr.Expr.Value(nil)
				if !diags.HasErrors() && val.Type().FriendlyName() == "string" {
					version = val.AsString()
				}
			}
		}

		if version == "" {
			continue
		}

		// Parse provider address to get the name
		// Format: registry.terraform.io/hashicorp/aws or just hashicorp/aws
		name := providerAddress
		// Remove quotes if present
		name = strings.Trim(name, "\"")

		pkgs = append(pkgs, &extractor.Package{
			Name:      name,
			Version:   version,
			PURLType:  purl.TypeTerraform,
			Locations: []string{input.Path},
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}
