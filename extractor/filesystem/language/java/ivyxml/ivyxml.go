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

// Package ivyxml extracts ivy.xml files.
package ivyxml

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/ivyxml"
)

// Extractor extracts Maven packages from ivy.xml files.
type Extractor struct{}

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

// FileRequired returns true if the specified file matches ivy.xml.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "ivy.xml"
}

// ivyModule represents the top-level ivy-module element.
type ivyModule struct {
	XMLName      xml.Name     `xml:"ivy-module"`
	Dependencies dependencies `xml:"dependencies"`
}

// dependencies represents the dependencies section.
type dependencies struct {
	XMLName      xml.Name     `xml:"dependencies"`
	Dependencies []dependency `xml:"dependency"`
}

// dependency represents a single dependency entry.
type dependency struct {
	XMLName xml.Name `xml:"dependency"`
	Org     string   `xml:"org,attr"`
	Name    string   `xml:"name,attr"`
	Rev     string   `xml:"rev,attr"`
	Conf    string   `xml:"conf,attr"`
}

func parseDepGroupVals(conf string) []string {
	if conf == "" {
		return []string{}
	}
	groups := make([]string, 0)
	// Split on ';' and ',' to get individual configuration entries.
	for _, part := range strings.FieldsFunc(conf, func(r rune) bool { return r == ';' || r == ',' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Each entry may be "from->to"; take the left side.
		if before, _, found := strings.Cut(part, "->"); found {
			before = strings.TrimSpace(before)
			if before != "" {
				groups = append(groups, before)
			}
		} else {
			groups = append(groups, part)
		}
	}
	return groups
}

// Extract extracts packages from ivy.xml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read input: %w", err)
	}

	var module ivyModule
	if err := xml.Unmarshal(content, &module); err != nil {
		log.Errorf("could not extract ivy.xml from %s: %v", input.Path, err)
		return inventory.Inventory{}, fmt.Errorf("could not extract ivy.xml from %s: %w", input.Path, err)
	}

	var packages []*extractor.Package
	lineTracker := newLineTracker(content)

	for _, dep := range module.Dependencies.Dependencies {
		if dep.Org == "" || dep.Name == "" || dep.Rev == "" {
			continue
		}

		metadata := javalockfile.Metadata{
			ArtifactID:   dep.Name,
			GroupID:      dep.Org,
			DepGroupVals: parseDepGroupVals(dep.Conf),
		}

		lineNum := lineTracker.findLine(dep.Org, dep.Name, dep.Rev)

		pkg := &extractor.Package{
			Name:     fmt.Sprintf("%s:%s", dep.Org, dep.Name),
			Version:  dep.Rev,
			PURLType: purl.TypeMaven,
			Location: extractor.LocationFromPathAndLine(filepath.ToSlash(input.Path), lineNum),
			Metadata: &metadata,
		}
		packages = append(packages, pkg)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}

// lineTracker tracks line numbers for dependency elements in the raw XML.
type lineTracker struct {
	lines []string
}

func newLineTracker(content []byte) *lineTracker {
	return &lineTracker{lines: strings.Split(string(content), "\n")}
}

func (lt *lineTracker) findLine(org, name, rev string) int {
	for i, line := range lt.lines {
		if strings.Contains(line, "org=\""+org+"\"") &&
			strings.Contains(line, "name=\""+name+"\"") &&
			strings.Contains(line, "rev=\""+rev+"\"") {
			return i + 1
		}
	}
	return 0
}
