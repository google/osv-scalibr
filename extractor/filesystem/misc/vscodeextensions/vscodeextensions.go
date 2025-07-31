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

// Package vscodeextensions extracts vscode extensions.
package vscodeextensions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Name is the name for the vscode extensions extractor
const Name = "vscode/extensions"

const extensionsSubPath = "/.vscode/extensions/extensions.json"

type extension struct {
	Identifier struct {
		ID string `json:"id"`
	} `json:"identifier"`
	Version  string `json:"version"`
	Location struct {
		Path string `json:"path"`
	} `json:"location"`
	Metadata Metadata `json:"metadata"`
}

func (e *extension) validate() error {
	if e.Identifier.ID == "" {
		return errors.New("extension 'Identifier.ID' cannot be empty")
	}
	if e.Version == "" {
		return errors.New("extension 'Version' cannot be empty")
	}
	return nil
}

// Extractor extracts vscode extensions
type Extractor struct{}

// New returns an vscode extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file contains vscode extensions information
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	path = filepath.ToSlash(path)
	return strings.HasSuffix(path, extensionsSubPath)
}

// Extract extracts vscode extensions
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var exts []*extension
	if err := json.NewDecoder(input.Reader).Decode(&exts); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	pkgs := make([]*extractor.Package, 0, len(exts))
	for _, ext := range exts {
		if err := ext.validate(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("bad format: %w", err)
		}
		pkgs = append(pkgs, &extractor.Package{
			Name:      ext.Identifier.ID,
			Version:   ext.Version,
			PURLType:  purl.TypeGeneric,
			Locations: []string{ext.Location.Path, input.Path},
			Metadata:  &ext.Metadata,
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}
