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

// Package projectassetsjson extracts project.assets.json files.
package projectassetsjson

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "dotnet/projectassetsjson"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

// Extractor extracts packages from inside a project.assets.json.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a requirements.txt extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.DotnetProjectAssetsJsonConfig {
		return c.GetDotnetProjectAssetsJson()
	})
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// projectAssetsJSON represents the `project.assets.json` file
type projectAssetsJSON struct {
	Targets   map[string]map[string]TargetPackage `json:"targets"`
	Libraries map[string]Library                  `json:"libraries"`
}

// TargetPackage represents a single package's info, including its version and its dependencies
type TargetPackage struct {
	Type         string            `json:"type"`
	Dependencies map[string]string `json:"dependencies"`
}

// Library represents a single library's info, including its version and its dependencies
type Library struct {
	Type string `json:"type"`
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is marked executable.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "project.assets.json" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > noLimitMaxFileSizeBytes && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract returns a list of dependencies in a project.assets.json file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(input)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	p, err := Parse(input.Reader)
	if err != nil {
		return nil, err
	}

	var res []*extractor.Package
	seen := make(map[string]struct{}) // dedup: name@version

	addPkg := func(name, version string) {
		if name == "" || version == "" {
			return
		}

		key := name + "@" + version
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}

		res = append(res, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeNuget,
			Location: extractor.LocationFromPath(input.Path),
		})
	}

	for _, packages := range p.Targets {
		for pkgKey, info := range packages {
			// Extract main package
			if info.Type == "package" {
				parts := strings.Split(pkgKey, "/")
				if len(parts) == 2 {
					addPkg(parts[0], parts[1])
				}
			}
			// Extract dependencies
			for depName, depVersion := range info.Dependencies {
				addPkg(depName, depVersion)
			}
		}
	}

	// Extract from libraries
	for libKey, lib := range p.Libraries {
		if lib.Type != "package" {
			continue
		}

		// Format: "PackageName/Version"
		parts := strings.Split(libKey, "/")
		if len(parts) != 2 {
			continue
		}

		addPkg(parts[0], parts[1])
	}

	return res, nil
}

// Parse returns a struct representing the structure of a .NET project's project.assets.json file.
func Parse(r io.Reader) (projectAssetsJSON, error) {
	dec := json.NewDecoder(r)
	var p projectAssetsJSON
	if err := dec.Decode(&p); err != nil {
		return projectAssetsJSON{}, fmt.Errorf("failed to decode project.assets.json file: %w", err)
	}

	return p, nil
}
