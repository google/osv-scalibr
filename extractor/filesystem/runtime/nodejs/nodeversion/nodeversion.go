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

// Package nodeversion extracts the Node.js version from .node-version files.
package nodeversion

import (
	"bufio"
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	meta "github.com/google/osv-scalibr/extractor/filesystem/runtime/nodejs/nodeversion/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "runtime/nodeversion"
)

// Extractor extracts Node.js versions.
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

// FileRequired returns true if the file name is '.node-version'.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == ".node-version"
}

func parseVersionLine(line string) (version string, ok bool) {
	line = strings.TrimSpace(line)
	// Comments and empty lines are ignored
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	// Remove 'v' prefix if present (e.g., v18.17.0 -> 18.17.0)
	version = strings.TrimPrefix(line, "v")
	// Skip if the version doesn't start with a digit.
	// This is for skipping special keywords like 'lts/*', 'node', 'system'.
	var startDigitRE = regexp.MustCompile(`^[0-9]`)
	if !startDigitRE.MatchString(version) {
		return "", false
	}
	return version, true
}

// Extract extracts Node.js version from the .node-version file.
//
// Reference: https://github.com/nodenv/node-build
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)
	var pkgs []*extractor.Package

	// .node-version files typically contain a single Node.js version,
	// But we'll read all lines in case there are comments
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		version, ok := parseVersionLine(scanner.Text())
		if !ok {
			continue
		}

		pkgs = append(pkgs, &extractor.Package{
			Name:      "nodejs",
			Version:   version,
			PURLType:  purl.TypeGeneric,
			Locations: []string{input.Path},
			Metadata: &meta.Metadata{
				NodeJsVersion: version,
			},
		})
		// We typically only expect one version per file
		break
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, err
	}
	return inventory.Inventory{Packages: pkgs}, nil
}
