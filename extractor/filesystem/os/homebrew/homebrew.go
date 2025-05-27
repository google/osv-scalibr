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

// Package homebrew extracts package information from OSX homebrew INSTALL_RECEIPT.json files.
package homebrew

import (
	"context"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/homebrew"

	caskPath       = "caskroom"
	cellarPath     = "cellar"
	cellarFileName = "install_receipt.json"
	caskFileName1  = ".wrapper.sh"
	caskFileName2  = "source.properties"
	caskFileName3  = ".app"
)

// BrewPath struct holds homebrew package information from homebrew package path.
// ../${appClass}/${appName}/${version}/${appFile}
// e.g. ../Caskroom/firefox/1.1/firefox.wrapper.sh or ../Cellar/tree/1.1/INSTALL_RECEIPT.json
type BrewPath struct {
	AppName    string
	AppVersion string
	AppFile    string
	AppExt     string
}

// Extractor extracts software details from a OSX Homebrew package path.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{OS: plugin.OSMac} }

// FileRequired returns true if the specified file path matches the homebrew path.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	filePath := strings.ToLower(api.Path())
	// Homebrew installs are in the following paths:
	// ../Cellar/${appName}/${version}/... or ../Caskroom/${appName}/${version}/...
	// Example of paths:
	// /usr/local/Cellar/... ; /opt/homebrew/Caskroom/... ; /usr/local/Caskroom/...;
	// /Users/emat/homebrew/Caskroom/... etc.
	// Ensure correct Homebrew path and file-name relationships are met for both Cellar and Caskroom.
	return isCellar(filePath) || isCaskroom(filePath)
}

// isCellar verifies Path to filename relationship.
func isCellar(filePath string) bool {
	// ../Cellar/${appName}/${version}/INSTALL_RECEIPT.json
	return strings.HasSuffix(filePath, cellarFileName) && strings.Contains(filePath, cellarPath)
}

// isCaskroom verifiesPath to filename relationships.
func isCaskroom(filePath string) bool {
	// ../Caskroom/${appName}/${version}/${appName}.wrapper.sh
	// or ../Caskroom/${appName}/${version}/${folder/source.properties|source.properties}
	// or ../Caskroom/${appName}/${version}/${appName}.app
	if !(strings.HasSuffix(filePath, caskFileName1) || strings.HasSuffix(filePath, caskFileName2) || strings.HasSuffix(filePath, caskFileName3)) {
		return false
	}

	return strings.Contains(filePath, caskPath)
}

// Extract parses the recognised Homebrew file path and returns information about the installed package.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	p := SplitPath(input.Path)
	if p == nil {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{Packages: []*extractor.Package{
		{
			Name:      p.AppName,
			Version:   p.AppVersion,
			PURLType:  purl.TypeBrew,
			Locations: []string{input.Path},
			Metadata:  &Metadata{},
		},
	}}, nil
}

// SplitPath takes the package path and splits it into its recognised struct components
func SplitPath(path string) *BrewPath {
	path = strings.ToLower(path)
	pathParts := strings.Split(path, "/")
	for i, pathPart := range pathParts {
		// Check if the path is a homebrew path and if the path is of a valid length.
		if (pathPart == cellarPath || pathPart == caskPath) && len(pathParts) > (i+3) {
			return &BrewPath{
				AppName:    pathParts[i+1],
				AppVersion: pathParts[i+2],
				AppFile:    pathParts[i+3],
				AppExt:     pathParts[len(pathParts)-1],
			}
		}
	}
	return nil
}
