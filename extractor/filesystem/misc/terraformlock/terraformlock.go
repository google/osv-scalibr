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

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/internal/hclparse"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "misc/terraformlock"
	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Extractor extracts Terraform providers from .terraform.lock.hcl files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a Terraform lock file extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.TerraformLock { return c.GetTerraformLock() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	e := &Extractor{maxFileSizeBytes: maxFileSizeBytes}
	return e, nil
}

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

	// Iterate through the body blocks to find provider blocks
	for i := range body.NamedChildCount() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		child := body.NamedChild(i)
		if child == nil {
			continue
		}

		if child.Type() != "block" || hclparse.GetBlockType(child, content) != "provider" {
			continue
		}

		// The provider block has a label which is the provider address
		providerAddress := hclparse.GetBlockLabel(child, content)
		if providerAddress == "" {
			continue
		}

		// Extract version from the block body attributes
		blockBody := hclparse.FindNamedChildByType(child, "body")
		if blockBody == nil {
			continue
		}

		_, version := hclparse.FindSourceAndVersionValues(blockBody, content)
		if version == "" {
			continue
		}

		// Parse provider address to get the name
		// Format: registry.terraform.io/hashicorp/aws or just hashicorp/aws
		name := strings.Trim(providerAddress, "\"")

		pkgs = append(pkgs, &extractor.Package{
			Name:      name,
			Version:   version,
			PURLType:  purl.TypeTerraform,
			Locations: []string{input.Path},
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}
