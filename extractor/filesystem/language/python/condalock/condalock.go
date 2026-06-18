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

// Package condalock extracts Conda explicit lockfiles (conda-*.lock).
package condalock

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"path"
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
	Name = "python/condalock"
	// MaxFileSize is the maximum size of a Conda explicit lockfile we will parse (10 MiB).
	MaxFileSize = 10 * 1024 * 1024
)

var knownExtensions = []string{
	".tar.bz2",
	".conda",
	".tar.gz",
	".tar.xz",
	".zip",
}

// Extractor extracts Conda packages from explicit lockfiles.
type Extractor struct{}

var _ filesystem.Extractor = Extractor{}

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

// FileRequired returns true if the specified file matches Conda explicit lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	p := path.Clean(filepath.ToSlash(api.Path()))
	base := path.Base(p)

	// Skip files inside node_modules or .git directories.
	for _, segment := range strings.Split(path.Dir(p), "/") {
		if segment == "node_modules" || segment == ".git" {
			return false
		}
	}

	if base == "conda.lock" {
		return true
	}
	matched, _ := path.Match("conda-*.lock", base)
	return matched
}

// Extract extracts packages from Conda explicit lockfiles passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info != nil && input.Info.Size() > MaxFileSize {
		return inventory.Inventory{}, fmt.Errorf("%s: file size %d exceeds maximum %d", Name, input.Info.Size(), MaxFileSize)
	}

	scanner := bufio.NewScanner(input.Reader)
	lineNum := 0
	packages := make([]*extractor.Package, 0)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", Name, err)
		}

		lineNum++
		pkg, err := parsePackageLine(scanner.Text(), input.Path, lineNum)
		if err != nil {
			return inventory.Inventory{}, err
		}
		if pkg != nil {
			packages = append(packages, pkg)
		}
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read file: %w", err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// parsePackageLine parses a single line from a Conda explicit lockfile.
// It returns nil, nil for lines that do not contain a package (comments, blanks, @EXPLICIT).
func parsePackageLine(line, filePath string, lineNum int) (*extractor.Package, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || line == "@EXPLICIT" {
		return nil, nil
	}

	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("invalid URL on line %d: %w", lineNum, err)
	}

	if u.Scheme == "" {
		return nil, fmt.Errorf("invalid URL on line %d: missing scheme", lineNum)
	}

	filename := path.Base(u.Path)
	if filename == "" {
		return nil, fmt.Errorf("empty filename on line %d", lineNum)
	}

	name, version, err := parseCondaFilename(filename)
	if err != nil {
		return nil, fmt.Errorf("line %d: %w", lineNum, err)
	}

	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeConda,
		Location: extractor.LocationFromPathAndLine(filePath, lineNum),
	}, nil
}

// parseCondaFilename extracts the package name and version from a Conda package filename.
// The filename format is: name-version-build.ext or name-version.ext
func parseCondaFilename(filename string) (name, version string, err error) {
	stem := filename
	for _, ext := range knownExtensions {
		if strings.HasSuffix(stem, ext) {
			stem = strings.TrimSuffix(stem, ext)
			break
		}
	}

	parts := strings.Split(stem, "-")
	for i, part := range parts {
		if isVersionSegment(part) {
			name = strings.Join(parts[:i], "-")
			version = part
			if name == "" {
				return "", "", fmt.Errorf("empty package name in filename %q", filename)
			}
			return name, version, nil
		}
	}

	return "", "", fmt.Errorf("could not find version in filename %q", filename)
}

// isVersionSegment reports whether a string segment looks like a Conda version number.
// A segment is considered a version if it starts with a digit and either contains a dot
// or consists entirely of digits.
func isVersionSegment(s string) bool {
	if s == "" {
		return false
	}
	if s[0] < '0' || s[0] > '9' {
		return false
	}
	hasDot := strings.Contains(s, ".")
	isNumeric := true
	for _, r := range s {
		if r < '0' || r > '9' {
			isNumeric = false
			break
		}
	}
	return hasDot || isNumeric
}
