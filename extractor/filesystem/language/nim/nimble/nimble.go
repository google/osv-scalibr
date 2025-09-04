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

// Package nimble extracts .nimble files from installed nimble packages.
package nimble

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "nim/nimble"
	// These two path slices can be used to determine Nimble package paths.
	pkgsPath  = "/pkgs/"
	pkgs2Path = "/pkgs2/"
)

// Extractor extracts nimble package info from .nimble files.
type Extractor struct{}

// New returns a nim nimble extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired return true if the specified file matched the .nimble file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	filePath := api.Path()
	if !strings.HasSuffix(filePath, ".nimble") {
		return false
	}
	if !(strings.Contains(filePath, pkgsPath) || strings.Contains(filePath, pkgs2Path)) {
		return false
	}
	return true
}

// This regexp is used to extract packageName and version from the folder name for both new and old versioning ex: /root/.nimble/pkgs2/json_serialization-0.4.2-2b26a9e0fc79638dbb9272fb4ab5a1d79264f938 or /root/.nimble/pkgs/gura-0.1.1"
var reFolder = regexp.MustCompile(`^(.*?)-([0-9]+(?:\.[0-9]+)*)(?:-[a-f0-9]+)?$`)

// Extract extracts Package info from .Nimble file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs := e.extractFromPath(input.Path)
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) extractFromPath(path string) []*extractor.Package {
	// Get the first folder before nimble file
	dirName := filepath.Base(filepath.Dir(path))
	match := reFolder.FindStringSubmatch(dirName)

	if len(match) == 3 {
		pkg := &extractor.Package{
			Name:      match[1],
			Version:   match[2],
			PURLType:  purl.TypeNim,
			Locations: []string{path},
		}
		return []*extractor.Package{pkg}
	}

	log.Errorf("failed to extract package version from the following path : %s", path)
	return nil
}
