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

// Package macports extracts package information from OSX macports Portfile files.
package macports

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	macportsmeta "github.com/google/osv-scalibr/extractor/filesystem/os/macports/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/macports"
)

// Extractor extracts macports apps.
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

// the Portfile file is found in /opt/local/var/macports/registry/portfiles/<packagename>-<version>_<revision>/<SHA256 hash of Portfile>-<index>/Portfile
var filePathRegex = regexp.MustCompile(`macports/registry/portfiles/([^-]+(?:-[^-]+)*)-([0-9][^_]*)_([0-9]+)/[a-f0-9]{64}-\d+/Portfile$`)

// This regex is used for extracting package name, version and revision from the directory name. Example directory name: autoconf-2.72_0
var portfileParsingRegex = regexp.MustCompile(`^(.+)-([0-9][^_]*)_(\d+)$`)

// FileRequired returns true if the specified file matches Portfile file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	filePath := api.Path()
	if !strings.HasSuffix(filePath, "Portfile") {
		return false
	}
	if match := filePathRegex.FindString(filePath); match == "" {
		return false
	}
	return true
}

// Extract extracts Port info from Portfile file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs := e.extractFromPath(input.Path)
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) extractFromPath(path string) []*extractor.Package {
	// Get the first folder after "portfiles/"
	dir := filepath.Base(filepath.Dir(filepath.Dir(path)))
	dir = strings.ToLower(dir)
	// Apply regex
	m := portfileParsingRegex.FindStringSubmatch(dir)

	if len(m) >= 4 {
		pkg := &extractor.Package{
			Name:      m[1],
			Version:   m[2],
			PURLType:  purl.TypeMacports,
			Locations: []string{path},
			Metadata: &macportsmeta.Metadata{
				PackageName:     m[1],
				PackageVersion:  m[2],
				PackageRevision: m[3],
			},
		}
		return []*extractor.Package{pkg}
	}
	return nil
}
