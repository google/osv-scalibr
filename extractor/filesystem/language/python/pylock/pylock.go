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

// Package pylock extracts pylock.toml files
package pylock

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pylock"
)

type pylockVCS struct {
	Type   string `toml:"type"`
	Commit string `toml:"commit-id"`
}

type pylockDirectory struct {
	Path string `toml:"path"`
}

type pylockPackage struct {
	Name      string          `toml:"name"`
	Version   string          `toml:"version"`
	VCS       pylockVCS       `toml:"vcs"`
	Directory pylockDirectory `toml:"directory"`
}

type pylockLockfile struct {
	Version  string          `toml:"lock-version"`
	Packages []pylockPackage `toml:"packages"`
}

// Extractor extracts python packages from pylock.toml files.
type Extractor struct{}

var _ filesystem.Extractor = Extractor{}

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

// FileRequired returns true if the specified file matches pylock lockfile patterns
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())

	if base == "pylock.toml" {
		return true
	}

	m, _ := filepath.Match("pylock.*.toml", base)

	return m
}

// Extract extracts packages from pylock.toml files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	var parsedLockfile pylockLockfile
	if err := toml.Unmarshal(content, &parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packageNames := make([]string, 0, len(parsedLockfile.Packages))
	for _, p := range parsedLockfile.Packages {
		packageNames = append(packageNames, p.Name)
	}
	lineNums := findPackageLineNumbers(content, packageNames)

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))

	for i, lockPackage := range parsedLockfile.Packages {
		// this is likely the root package, which is sometimes included in the lockfile
		if lockPackage.Version == "" && lockPackage.Directory.Path == "." {
			continue
		}

		pkgDetails := &extractor.Package{
			Name:     lockPackage.Name,
			Version:  lockPackage.Version,
			PURLType: purl.TypePyPi,
			Location: extractor.LocationFromPathAndLine(input.Path, lineNums[i]),
		}
		if lockPackage.VCS.Commit != "" {
			pkgDetails.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: lockPackage.VCS.Commit,
			}
		}
		packages = append(packages, pkgDetails)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// extractPackageName parses a TOML key-value line and returns the unquoted
// package name if the key is "name". Returns false if the line is not a valid name assignment.
// TODO(b/491518484): Put in common location for all Python extractors to use.
func extractPackageName(line string) (string, bool) {
	if !strings.HasPrefix(line, "name") {
		return "", false
	}
	k, _, ok := strings.Cut(line, "=")
	if !ok || strings.TrimSpace(k) != "name" {
		return "", false
	}
	var pkg pylockPackage
	if err := toml.Unmarshal([]byte(line), &pkg); err != nil {
		return "", false
	}
	return pkg.Name, true
}

// findPackageLineNumbers returns the line numbers of the specified package names.
// If package line number is not found, the value will be 0.
func findPackageLineNumbers(content []byte, packageNames []string) []int {
	lineNums := make([]int, len(packageNames))
	if len(packageNames) == 0 {
		return lineNums
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	pkgIdx := 0
	inPackageBlock := false
	inPackageList := false
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Check where we are in the file based on line content.
		switch {
		case line == "[[packages]]":
			inPackageBlock = true
			inPackageList = false
			continue
		case strings.HasPrefix(line, "packages = ["):
			inPackageList = true
			inPackageBlock = false
			continue
		case inPackageBlock && strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[packages]]"):
			inPackageBlock = false
			continue
		case inPackageList && line == "]":
			inPackageList = false
			continue
		}

		// Only process lines in a package block or package list.
		if !inPackageBlock && !inPackageList || pkgIdx >= len(packageNames) {
			continue
		}

		// Extract package.
		name, ok := extractPackageName(line)
		if !ok || name != packageNames[pkgIdx] {
			continue
		}

		lineNums[pkgIdx] = lineNum
		pkgIdx++

		// Stop checking lines in this specific [[packages]] block, and move on to the next.
		if inPackageBlock {
			inPackageBlock = false
		}

		// If all package names found, exit early.
		if pkgIdx == len(packageNames) {
			break
		}
	}
	return lineNums
}

var _ filesystem.Extractor = Extractor{}
