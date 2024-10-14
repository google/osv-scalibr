// Copyright 2024 Google LLC
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
	"io/fs"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	caskPath       = "caskroom"
	cellarPath     = "cellar"
	cellarFileName = "install_receipt.json"
	caskFileName1  = ".wrapper.sh"
	caskFileName2  = ".app"
	caskFileName3  = "source.properties"
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

var r = regexp.MustCompile(`(\bcellar|\bcaskroom)\/(.*)\/[^A-Za-z \/]+\/`)

// Extractor extracts software details from a OSX Homebrew package path.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return "os/homebrew" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{OS: plugin.OSMac} }

// FileRequired returns true if the specified file path matches the homebrew path.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	filePath := strings.ToLower(path)
	// Homebrew installs reference paths  /usr/local/Cellar/ and /usr/local/Caskroom
	// Ensure correct Homebrew path regex before attempting to split the path into its components:
	// ../Cellar/${appName}/${version}/INSTALL_RECEIPT.json or ../Caskroom/${appName}/${version}/${appName.wrapper.sh}
	if !r.MatchString(filePath) {
		return false
	}

	p := SplitPath(filePath)
	// Ensure the file path is a valid homebrew Cellar file.
	if strings.Contains(filePath, cellarPath) && p.AppFile != cellarFileName {
		return false
	}
	// Ensure the file path is a valid homebrew Caskroom file.
	if strings.Contains(filePath, caskPath) && !strings.Contains(p.AppExt, caskFileName1) && !strings.Contains(p.AppExt, caskFileName2) && !strings.Contains(p.AppExt, caskFileName3) {
		return false
	}
	return true
}

// Extract parses the recognised Homebrew file path and returns information about the installed package.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	p := SplitPath(input.Path)
	if p == nil {
		return []*extractor.Inventory{}, nil
	}
	return []*extractor.Inventory{
		&extractor.Inventory{
			Name:      p.AppName,
			Version:   p.AppVersion,
			Locations: []string{input.Path},
		},
	}, nil
}

// SplitPath takes the package path and splits it into its recognised struct components
func SplitPath(path string) *BrewPath {
	path = strings.ToLower(path)
	pathParts := strings.Split(path, "/")
	for i, pathPart := range pathParts {
		// Check if the path is a homebrew path and if the path is of a valid length.
		if len(pathParts) > (i+3) && (pathPart == caskPath || pathPart == cellarPath) {
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

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypeBrew,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "brew" }
