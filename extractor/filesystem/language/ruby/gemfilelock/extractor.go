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

// Package gemfilelock extracts Gemfile.lock files.
package gemfilelock

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

var (
	// Gemfile.lock spec lines follow the format "name (version)"
	nameVersionRegexp = regexp.MustCompile(`^(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$`)
	indentRegexp      = regexp.MustCompile(`^( +)`)
)

// Extractor extracts package info from Gemfile.lock files.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return "ruby/gemfilelock" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired return true if the specified file is a Gemfile.lock file.
func (e Extractor) FileRequired(path string, _ func() (fs.FileInfo, error)) bool {
	return filepath.Base(path) == "Gemfile.lock"
}

type gemlockSection struct {
	name     string
	revision string
	specs    []string
}

func parseLockfileSections(input *filesystem.ScanInput) ([]*gemlockSection, error) {
	sections := []*gemlockSection{}
	var currentSection *gemlockSection
	scanner := bufio.NewScanner(input.Reader)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error while scanning %s: %w", input.Path, err)
		}
		line := scanner.Text()
		if len(line) == 0 {
			// Skip empty lines.
			continue
		}
		m := indentRegexp.FindStringSubmatch(line)
		if m == nil { // No spaces at the start, this is a new section.
			if currentSection != nil {
				sections = append(sections, currentSection)
			}
			currentSection = &gemlockSection{name: line}
		} else if len(m[0]) == 4 {
			// Indented with 4 spaces: This line contains a top-level spec for the current section.
			if currentSection == nil {
				return nil, fmt.Errorf("%s: invalid lockfile: specs entry before a section declaration", input.Path)
			}
			currentSection.specs = append(currentSection.specs, strings.TrimPrefix(line, "    "))
		} else if strings.HasPrefix(line, "  revision: ") {
			// The commit for the given section. Always stored at an indentation level of 2.
			if currentSection == nil {
				return nil, fmt.Errorf("%s: invalid lockfile: revision entry before a section declaration", input.Path)
			}
			currentSection.revision = strings.TrimPrefix(line, "  revision: ")
		}
		// We don't store info about any other entries at the moment.
	}
	// Append the trailing section too.
	if currentSection != nil {
		sections = append(sections, currentSection)
	}
	return sections, nil
}

func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	sections, err := parseLockfileSections(input)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", input.Path, err)
	}

	invs := []*extractor.Inventory{}
	for _, section := range sections {
		if !slices.Contains([]string{"GIT", "GEM", "PATH", "PLUGIN SOURCE"}, section.name) {
			// Not a source section.
			continue
		}
		for _, s := range section.specs {
			m := nameVersionRegexp.FindStringSubmatch(s)
			if len(m) < 3 || m[1] == "" || m[2] == "" {
				log.Errorf("Invalid spec line: %s", s)
				continue
			}
			name, version := m[1], m[2]
			i := &extractor.Inventory{
				Name:      name,
				Version:   version,
				Locations: []string{input.Path},
			}
			if section.revision != "" {
				i.SourceCode = &extractor.SourceCodeIdentifier{
					Commit: section.revision,
				}
			}
			invs = append(invs, i)
		}
	}
	return invs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeGem,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return "RubyGems"
}

var _ filesystem.Extractor = Extractor{}
