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

// Package denojson extracts deno.json files.
package denojson

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denohelper"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/denojson"
)

type denoJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Imports map[string]string `json:"imports"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// MaxFileSizeBytes is the maximum size of a file that can be extracted.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored by returning false for `FileRequired`.
	MaxFileSizeBytes int64
}

// Extractor extracts javascript packages from deno.json files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a new deno.json extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{maxFileSizeBytes: cfg.MaxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches deno.json pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	// Check for deno.json files
	if filepath.Base(path) == "deno.json" {
		fileinfo, err := api.Stat()
		if err != nil {
			return false
		}
		if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
			return false
		}
		return true
	}

	return false
}

// Extract extracts packages from deno.json files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	path := input.Path

	// Parse deno.json files
	pkgs, err := parseDenoJSONFile(path, input.Reader)
	if err != nil {
		return inventory.Inventory{},
			fmt.Errorf("error during parsing the deno.json: %w", err)
	}

	for _, p := range pkgs {
		p.Locations = []string{path}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

func parseDenoJSONFile(path string, r io.Reader) ([]*extractor.Package, error) {
	dec := json.NewDecoder(r)

	var p denoJSON
	if err := dec.Decode(&p); err != nil {
		log.Debugf("deno.json file %s json decode failed: %v", path, err)
		return nil, fmt.Errorf("failed to parseDenoJSONFile deno.json file: %w", err)
	}

	if !p.hasNameAndVersionValues() {
		log.Debugf("deno.json file %s does not have a version and/or name", path)
		return nil, nil
	}

	var pkgs []*extractor.Package

	if len(p.Imports) > 0 {
		for _, importSpec := range p.Imports {
			pkg := denohelper.ParseImportSpecifier(importSpec)
			if pkg != nil {
				pkgs = append(pkgs, pkg)
			}
		}
	}

	return pkgs, nil
}

func (p denoJSON) hasNameAndVersionValues() bool {
	return p.Name != "" && p.Version != ""
}
