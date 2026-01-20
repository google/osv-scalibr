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

// Package mise extracts the installed language runtime names and versions from mise.toml files.
package mise

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	misemeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/mise/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "runtime/mise"
)

// Extractor extracts mise tools.
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

// FileRequired returns true if the file matches any of the mise config file paths.
// Supported paths (in order of precedence):
//   - mise.local.toml (local config, should not be committed)
//   - .config/mise.toml
//   - mise.toml
//   - mise/config.toml
//   - .mise/config.toml
//   - .config/mise/config.toml
//   - .config/mise/conf.d/*.toml
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := path.Base(api.Path())
	dir := path.Dir(api.Path())

	// Check for mise.local.toml in any directory
	if base == "mise.local.toml" {
		return true
	}

	// Check for .config/mise.toml
	if base == "mise.toml" && path.Base(dir) == ".config" {
		return true
	}

	// Check for mise.toml in any directory (except .config, which is handled above)
	if base == "mise.toml" {
		return true
	}

	// Check for mise/config.toml
	if base == "config.toml" && path.Base(dir) == "mise" {
		return true
	}

	// Check for .mise/config.toml
	if base == "config.toml" && path.Base(dir) == ".mise" {
		return true
	}

	// Check for .config/mise/config.toml
	if base == "config.toml" && strings.HasSuffix(dir, ".config/mise") {
		return true
	}

	// Check for .config/mise/conf.d/*.toml
	if path.Ext(base) == ".toml" && strings.HasSuffix(dir, ".config/mise/conf.d") {
		return true
	}

	return false
}

// miseTomlFile represents the structure of a mise.toml file.
type miseTomlFile struct {
	Tools map[string]any `toml:"tools"`
}

// Extract extracts packages from the mise.toml file.
//
// Reference: https://mise.jdx.dev/configuration.html
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedTomlFile miseTomlFile
	_, err := toml.NewDecoder(input.Reader).Decode(&parsedTomlFile)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	var pkgs []*extractor.Package
	for tool, value := range parsedTomlFile.Tools {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		var version string
		switch v := value.(type) {
		case string:
			// Simple string version: terraform = "1"
			version = v
		case map[string]any:
			// Object with options like: ToolName = { version = "22", ...}
			if ver, ok := v["version"].(string); ok {
				version = ver
			}
		}

		// Skip if no version was found
		if version == "" {
			continue
		}

		pkgs = append(pkgs, &extractor.Package{
			Name:      tool,
			Version:   version,
			PURLType:  purl.TypeMise,
			Locations: []string{input.Path},
			Metadata: &misemeta.Metadata{
				ToolName:    tool,
				ToolVersion: version,
			},
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}
