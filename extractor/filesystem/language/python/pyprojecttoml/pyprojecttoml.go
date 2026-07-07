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

// Package pyprojecttoml extracts dependencies from pyproject.toml files.

package pyprojecttoml

import (
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pyprojecttoml"
)

// regexes (regices?) for PEP 508
var (
	reUnsupportedConstraints = regexp.MustCompile(`\*|<[^=]|,|!=`)
	reWhitespace           = regexp.MustCompile(`[ \t\r]`)
	reValidPkg             = regexp.MustCompile(`^\w(\w|-)+$`)
	reExtras               = regexp.MustCompile(`\[[^\[\]]*\]`)
)

// pyprojectFile represents the structure of a pyproject.toml file
type pyprojectFile struct {
	Project projectTable `toml:"project"`
}

// projectTable represents the [project] table as defined by PEP 621
type projectTable struct {
	Dependencies         []string            `toml:"dependencies"`
	OptionalDependencies map[string][]string `toml:"optional-dependencies"`
}

// Extractor extracts Python packages from pyproject.toml files
type Extractor struct{}

var _ filesystem.Extractor = Extractor{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

//Requirements of the extractor. 
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true only for files named exactly "pyproject.toml".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pyproject.toml"
}

// Extract extracts packages from the [project] table of a pyproject.toml file.
func (e Extractor) Extract(
	_ context.Context, input *filesystem.ScanInput,
) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	var f pyprojectFile
	if err := toml.Unmarshal(content, &f); err != nil {
		// malformed TOML = return empty inventory. 
		return inventory.Inventory{}, nil
	}

	// No [project] table or no dependencies declared.
	if len(f.Project.Dependencies) == 0 &&
		len(f.Project.OptionalDependencies) == 0 {
		return inventory.Inventory{}, nil
	}

	var pkgs []*extractor.Package

	for _, dep := range f.Project.Dependencies {
		if pkg := parseDep(dep, input.Path); pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}

	for _, deps := range f.Project.OptionalDependencies {
		for _, dep := range deps {
			if pkg := parseDep(dep, input.Path); pkg != nil {
				pkgs = append(pkgs, pkg)
			}
		}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// parseDep parses a single PEP 508 dependency string and returns a package, or nil if the string is invalid or unsupported
func parseDep(dep, path string) *extractor.Package {
	s := removeWhiteSpaces(dep)
	s = ignorePythonSpecifier(s)
	s = removeExtras(s)

	if len(s) == 0 {
		return nil
	}

	name, version, comp := getLowestVersion(s)
	if name == "" {
		return nil
	}
	if version == "" && comp != "" {
		return nil
	}
	if !isValidPackage(name) {
		return nil
	}

	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypePyPi,
		Location: extractor.LocationFromPath(
			filepath.ToSlash(path),
		),
		Metadata: &requirements.Metadata{
			VersionComparator: comp,
			Requirement:       dep,
		},
	}
}

// ignorePythonSpecifier strips environment markers from a PEP 508 string.
// TODO(b/491518484): Put in common location for all Python extractors to use (applies to all the below functions).
func ignorePythonSpecifier(s string) string {
	return strings.SplitN(s, ";", 2)[0]
}

// removeExtras strips extras from a PEP 508 package name.
func removeExtras(s string) string {
	return reExtras.ReplaceAllString(s, "")
}

// removeWhiteSpaces removes spaces, tabs, and carriage returns.
func removeWhiteSpaces(s string) string {
	return reWhitespace.ReplaceAllString(s, "")
}

// isValidPackage returns true if s looks like a valid PyPI package name.
func isValidPackage(s string) bool {
	return reValidPkg.MatchString(s)
}

// nameFromRequirement extracts just the package name from a PEP 508 string.
func nameFromRequirement(s string) string {
	for _, sep := range []string{"===", "==", ">=", "<=", "~=", "!=", "<"} {
		s, _, _ = strings.Cut(s, sep)
	}
	return s
}

// getLowestVersion parses a PEP 508 string into name, version, and comparator.
func getLowestVersion(s string) (name, version, comparator string) {
	if reUnsupportedConstraints.FindString(s) != "" {
		return nameFromRequirement(s), "", ""
	}

	separators := []string{"===", "==", ">=", "<=", "~="}
	for _, sep := range separators {
		if strings.Contains(s, sep) {
			t := strings.SplitN(s, sep, 2)
			if len(t) != 2 {
				return "", "", ""
			}
			return t[0], t[1], sep
		}
	}

	// no version constraint
	return s, "", ""
}
