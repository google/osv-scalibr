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

// Package rpkg extracts installed R packages from DESCRIPTION files.
//
// When R packages are installed via install.packages(), BiocManager, or similar
// tools, each package is placed in a library directory
// (e.g. /usr/lib/R/library/<package>/) with a DESCRIPTION file containing
// metadata in the Debian control file (DCF) format. This extractor scans for
// those DESCRIPTION files to enumerate all installed R packages and match them
// against the CRAN ecosystem in OSV.dev.
//
// File pattern: <R_lib_path>/<PackageName>/DESCRIPTION
// Example: /usr/lib/R/library/ggplot2/DESCRIPTION
package rpkg

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "r/rpkg"
)

// Extractor extracts installed R packages from DESCRIPTION files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is a DESCRIPTION file inside an R library directory.
//
// R library layout:
//
//	<lib>/<PackageName>/DESCRIPTION
//
// We match any file named "DESCRIPTION" where the grandparent directory name
// looks like an R library root (contains typical R package directories like
// "base", "utils", "stats" siblings, or is under a path containing "R/library",
// "R/site-library", or "R/x86_64-pc-linux-gnu-library").
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())

	// The filename must be exactly "DESCRIPTION".
	if filepath.Base(path) != "DESCRIPTION" {
		return false
	}

	// The path must be at least 2 levels deep: <lib>/<pkg>/DESCRIPTION
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return false
	}

	// Accept paths that contain well-known R library directory patterns.
	return isRLibraryPath(path)
}

// isRLibraryPath returns true if the given path looks like an R library package path.
func isRLibraryPath(path string) bool {
	rLibPatterns := []string{
		"/R/library/",
		"/R/site-library/",
		"/R/x86_64-",
		"/R/aarch64-",
		"/R/arm-",
		"site-packages/R/", // Some conda R environments
		"lib/R/",
		"Library/R/",  // macOS R library
		"r-packages/", // Some Linux distros
	}
	for _, pat := range rLibPatterns {
		if strings.Contains(path, pat) {
			return true
		}
	}
	return false
}

// Extract extracts the R package name and version from an R DESCRIPTION file.
//
// The DESCRIPTION file uses the Debian Control File (DCF) format, a simple
// key-value format where each field is on its own line:
//
//	Package: ggplot2
//	Version: 3.4.4
//	Title: Create Elegant Data Visualisations Using the Grammar of Graphics
//	...
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkg, err := parseDESCRIPTION(input)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("rpkg: parseDESCRIPTION(%s): %w", input.Path, err)
	}
	if pkg == nil {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{Packages: []*extractor.Package{pkg}}, nil
}

// parseDESCRIPTION parses an R DESCRIPTION file and returns an extractor.Package.
// Returns nil if the file does not contain a valid R package (missing Package or Version fields).
func parseDESCRIPTION(input *filesystem.ScanInput) (*extractor.Package, error) {
	fields := make(map[string]string)

	scanner := bufio.NewScanner(input.Reader)
	var currentKey string
	for scanner.Scan() {
		line := scanner.Text()

		// Skip blank lines (DCF block separators — R DESCRIPTION has only one block).
		if line == "" {
			continue
		}

		// Continuation lines start with whitespace.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if currentKey != "" {
				fields[currentKey] += " " + strings.TrimSpace(line)
			}
			continue
		}

		// Key: Value line
		before, after, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		currentKey = strings.TrimSpace(before)
		value := strings.TrimSpace(after)
		fields[currentKey] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	pkgName := fields["Package"]
	version := fields["Version"]

	// Both Package and Version are required to produce a meaningful inventory entry.
	if pkgName == "" || version == "" {
		return nil, nil
	}

	return &extractor.Package{
		Name:     pkgName,
		Version:  version,
		PURLType: purl.TypeCran,
		Location: extractor.LocationFromPath(input.Path),
	}, nil
}
