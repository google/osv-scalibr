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

// Package composerinstalled extracts Composer installed.json files.
package composerinstalled

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/linefinder"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "php/composerinstalled"
)

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Reference string `json:"reference"`
	} `json:"dist"`
}

type installedFile struct {
	Packages        []composerPackage `json:"packages"`
	DevPackageNames []string          `json:"dev-package-names"`
}

// Extractor extracts Composer installed package inventories.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e *Extractor) Name() string { return Name }

// Version of the extractor.
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true for Composer installed.json files.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return filepath.Base(path) == "installed.json" &&
		filepath.Base(filepath.Dir(path)) == "composer"
}

// Extract extracts packages from a Composer installed.json file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages, devPackageNames, linePrefix, err := parseInstalledFile(data)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	devPackages := make(map[string]struct{}, len(devPackageNames))
	for _, name := range devPackageNames {
		devPackages[name] = struct{}{}
	}

	finder := linefinder.NewJSONLineFinder(data)
	result := make([]*extractor.Package, 0, len(packages))
	for i, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{Packages: result}, err
		}

		groups := []string{}
		if _, ok := devPackages[pkg.Name]; ok {
			groups = append(groups, "dev")
		}
		line := finder.LineOf(fmt.Sprintf("%s%d.name", linePrefix, i))
		result = append(result, buildPackage(input.Path, pkg, line, groups))
	}

	return inventory.Inventory{Packages: result}, nil
}

func buildPackage(path string, pkg composerPackage, line int, groups []string) *extractor.Package {
	commit := pkg.Dist.Reference

	// A dot means the reference is likely a tag rather than a commit.
	if strings.Contains(commit, ".") {
		commit = ""
	}

	return &extractor.Package{
		Name:     pkg.Name,
		Version:  pkg.Version,
		PURLType: purl.TypeComposer,
		Location: extractor.LocationFromPathAndLine(path, line),
		SourceCode: &extractor.SourceCodeIdentifier{
			Commit: commit,
		},
		Metadata: &osv.DepGroupMetadata{
			DepGroupVals: groups,
		},
	}
}

func parseInstalledFile(data []byte) ([]composerPackage, []string, string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil, "", errors.New("empty JSON document")
	}

	switch trimmed[0] {
	case '[':
		var packages []composerPackage
		if err := json.Unmarshal(trimmed, &packages); err != nil {
			return nil, nil, "", err
		}
		if packages == nil {
			return nil, nil, "", errors.New("decoded null package list")
		}
		return packages, nil, "", nil
	case '{':
		var installed installedFile
		if err := json.Unmarshal(trimmed, &installed); err != nil {
			return nil, nil, "", err
		}
		if installed.Packages == nil {
			return nil, nil, "", errors.New("installed.json is missing packages")
		}
		return installed.Packages, installed.DevPackageNames, "packages.", nil
	default:
		return nil, nil, "", errors.New("installed.json must contain an object or array")
	}
}

var _ filesystem.Extractor = (*Extractor)(nil)
