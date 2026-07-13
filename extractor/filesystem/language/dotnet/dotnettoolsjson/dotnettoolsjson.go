// Copyright 2026 Google LLC
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

// Package dotnettoolsjson extracts .NET local tools from dotnet-tools.json manifests.
package dotnettoolsjson

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "dotnet/dotnettoolsjson"
	// MaxFileSize is the maximum size of a dotnet-tools.json we will parse (1 MB).
	MaxFileSize = 1024 * 1024
)

// toolsManifest is the root structure of a dotnet-tools.json file.
type toolsManifest struct {
	Version int                `json:"version"`
	IsRoot  bool               `json:"isRoot"`
	Tools   map[string]toolDef `json:"tools"`
}

type toolDef struct {
	Version  string   `json:"version"`
	Commands []string `json:"commands"`
}

// Extractor extracts .NET local tools from dotnet-tools.json manifests.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file is a dotnet-tools.json.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "dotnet-tools.json"
}

// Extract extracts .NET local tools from the dotnet-tools.json file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info != nil && input.Info.Size() > MaxFileSize {
		return inventory.Inventory{}, fmt.Errorf("%s: file size %d exceeds maximum %d", Name, input.Info.Size(), MaxFileSize)
	}

	var manifest toolsManifest
	decoder := json.NewDecoder(input.Reader)
	if err := decoder.Decode(&manifest); err != nil {
		return inventory.Inventory{}, fmt.Errorf("%s: failed to decode JSON: %w", Name, err)
	}

	toolNames := make([]string, 0, len(manifest.Tools))
	for toolName := range manifest.Tools {
		toolNames = append(toolNames, toolName)
	}
	sort.Strings(toolNames)

	var packages []*extractor.Package
	if len(toolNames) > 0 {
		packages = make([]*extractor.Package, 0, len(toolNames))
	}
	for _, toolName := range toolNames {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", Name, err)
		}
		tool := manifest.Tools[toolName]
		packages = append(packages, &extractor.Package{
			Name:     toolName,
			Version:  tool.Version,
			PURLType: purl.TypeNuget,
			Location: extractor.LocationFromPath(input.Path),
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
