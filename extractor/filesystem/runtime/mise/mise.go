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

// FileRequired returns true if the file name is 'mise.toml'.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == "mise.toml"
}

// miseTomlFile represents the structure of a mise.toml file.
type miseTomlFile struct {
	Tools map[string]string `toml:"tools"`
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
	for tool, version := range parsedTomlFile.Tools {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
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
