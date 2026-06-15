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

// Package description extracts R dependency declarations from DESCRIPTION manifests.
package description

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "r/description"
)

var depFields = map[string]bool{
	"Depends":   true,
	"Imports":   true,
	"Suggests":  true,
	"Enhances":  true,
	"LinkingTo": true,
}

var depGroups = map[string]string{
	"Depends":   "depends",
	"Imports":   "imports",
	"Suggests":  "suggests",
	"Enhances":  "enhances",
	"LinkingTo": "linkingto",
}

// Extractor extracts R dependency declarations from DESCRIPTION files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches a DESCRIPTION file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "DESCRIPTION"
}

// Extract extracts R dependency declarations from DESCRIPTION files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	s := bufio.NewScanner(input.Reader)
	packages := make([]*extractor.Package, 0)
	var currentField string
	var currentValue strings.Builder

	flushField := func() {
		if currentField == "" {
			return
		}
		if depFields[currentField] {
			value := strings.TrimSpace(currentValue.String())
			group := depGroups[currentField]
			for _, pkg := range parseDepField(value, input.Path, group) {
				if pkg != nil {
					packages = append(packages, pkg)
				}
			}
		}
		currentField = ""
		currentValue.Reset()
	}

	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		line := s.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Check if this is a new field line (starts with non-whitespace, contains a colon).
		if !isContinuationLine(line) {
			flushField()
			if colonIdx := strings.Index(line, ":"); colonIdx > 0 {
				fieldName := strings.TrimSpace(line[:colonIdx])
				fieldValue := strings.TrimSpace(line[colonIdx+1:])
				currentField = fieldName
				currentValue.WriteString(fieldValue)
			}
		} else {
			// Continuation line - append to current field value.
			currentValue.WriteString(" ")
			currentValue.WriteString(trimmed)
		}
	}
	flushField()

	if err := s.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("error while scanning DESCRIPTION: %w", err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

func isContinuationLine(line string) bool {
	if len(line) == 0 {
		return false
	}
	// DCF continuation lines start with a space or tab.
	first := line[0]
	return first == ' ' || first == '\t'
}

func parseDepField(value, path, group string) []*extractor.Package {
	if value == "" {
		return nil
	}
	var packages []*extractor.Package
	entries := splitCommaEntries(value)
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name := extractPackageName(entry)
		if name == "" || name == "R" {
			continue
		}
		pkg := &extractor.Package{
			Name:     name,
			PURLType: purl.TypeCran,
			Location: extractor.LocationFromPath(path),
			Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{group}},
		}
		packages = append(packages, pkg)
	}
	return packages
}

func splitCommaEntries(s string) []string {
	var entries []string
	var current strings.Builder
	inParens := 0
	for i := range len(s) {
		c := s[i]
		if c == '(' {
			inParens++
			current.WriteByte(c)
		} else if c == ')' {
			inParens--
			current.WriteByte(c)
		} else if c == ',' && inParens == 0 {
			entries = append(entries, current.String())
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		entries = append(entries, current.String())
	}
	return entries
}

func extractPackageName(entry string) string {
	// The package name is everything before the first '(' (version constraint).
	name, _, _ := strings.Cut(entry, "(")
	return strings.TrimSpace(name)
}

var _ filesystem.Extractor = Extractor{}
