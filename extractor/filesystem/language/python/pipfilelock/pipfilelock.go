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

// Package pipfilelock extracts Pipfile.lock files.
package pipfilelock

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pipfilelock"

	// JSON keys for relevant package groups in pipfilelock.
	jsonGroupDefault = "default"
	jsonGroupDevelop = "develop"

	// Keyword that SCALIBR uses for packages in the dev group.
	groupDev = "dev"
)

type pipenvPackage struct {
	Version string `json:"version"`
}

type pipenvLockFile struct {
	Packages    map[string]pipenvPackage `json:"default"`
	PackagesDev map[string]pipenvPackage `json:"develop"`
}

// Extractor extracts python packages from Pipfile.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Pipenv lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Pipfile.lock"
}

// Extract extracts packages from Pipfile.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read: %w", err)
	}

	var parsedLockfile *pipenvLockFile
	err = json.Unmarshal(content, &parsedLockfile)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	details := make(map[string]*extractor.Package)

	addPkgDetails(input.Path, content, details, parsedLockfile.Packages, "")
	addPkgDetails(input.Path, content, details, parsedLockfile.PackagesDev, groupDev)

	return inventory.Inventory{Packages: slices.Collect(maps.Values(details))}, nil
}

func addPkgDetails(path string, content []byte, details map[string]*extractor.Package, packages map[string]pipenvPackage, group string) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		// All pipenv package versions should be pinned with a ==
		// If it is not, this lockfile is not in the format we expect.
		if !strings.HasPrefix(pipenvPackage.Version, "==") || len(pipenvPackage.Version) < 3 {
			// Potentially log a warning here
			continue
		}

		version := pipenvPackage.Version[2:]

		// Because in the caller, prod packages are added first,
		// if it also exists in dev we don't want to add it to dev group
		if _, ok := details[name+"@"+version]; !ok {
			groupSlice := []string{}
			if group != "" {
				groupSlice = []string{group}
			}

			jsonGroup := jsonGroupDefault
			if group == groupDev {
				jsonGroup = jsonGroupDevelop
			}
			line := findLineNumber(content, jsonGroup, name)

			var loc extractor.PackageLocation
			if line > 0 {
				loc = extractor.LocationFromPathAndLine(path, line)
			} else {
				log.Debugf("Failed to find line number for package %s in group %s of %s", name, jsonGroup, path)
				loc = extractor.LocationFromPath(path)
			}

			pkg := &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypePyPi,
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: groupSlice,
				},
				Location: loc,
			}

			details[name+"@"+version] = pkg
		}
	}
}

// findLineNumber scans the JSON content to find the line number of a package.
func findLineNumber(content []byte, group string, pkgName string) int {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	currentGroup := ""
	lineIdx := 0

	defaultPrefix := fmt.Sprintf(`"%s":`, jsonGroupDefault)
	developPrefix := fmt.Sprintf(`"%s":`, jsonGroupDevelop)
	expectedKey := fmt.Sprintf(`"%s":`, pkgName)

	for scanner.Scan() {
		lineIdx++
		trimmed := strings.TrimSpace(scanner.Text())

		// Detect group block in the JSON file.
		if strings.HasPrefix(trimmed, defaultPrefix) {
			currentGroup = jsonGroupDefault
			continue
		}
		if strings.HasPrefix(trimmed, developPrefix) {
			currentGroup = jsonGroupDevelop
			continue
		}

		// If we are in the target group, look for the package name.
		if currentGroup == group {
			if strings.HasPrefix(trimmed, expectedKey) {
				return lineIdx
			}
		}
	}
	return 0
}

var _ filesystem.Extractor = Extractor{}
