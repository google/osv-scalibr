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

// Package cabalfile extracts Haskell dependency declarations from .cabal manifests.
package cabalfile

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
	Name = "haskell/cabalfile"
)

// Extractor extracts Haskell dependency declarations from .cabal files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches a .cabal file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Ext(api.Path()) == ".cabal"
}

// Extract extracts Haskell dependency declarations from .cabal files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	s := bufio.NewScanner(input.Reader)
	packages := make([]*extractor.Package, 0)

	var collectingField string
	var collectedValue strings.Builder

	flush := func() {
		if collectingField == "" {
			return
		}
		if strings.EqualFold(collectingField, "build-depends") || strings.EqualFold(collectingField, "build-tool-depends") {
			value := strings.TrimSpace(collectedValue.String())
			for _, entry := range splitCommaEntries(value) {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				name := extractPackageName(entry)
				if name != "" {
					packages = append(packages, &extractor.Package{
						Name:     name,
						PURLType: purl.TypeHaskell,
						Location: extractor.LocationFromPath(input.Path),
					})
				}
			}
		}
		collectingField = ""
		collectedValue.Reset()
	}

	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		rawLine := s.Text()
		trimmed := strings.TrimSpace(rawLine)

		// Skip blank lines and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}

		// Check if this is a continuation line (starts with whitespace).
		isContinuation := len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t')

		if isContinuation {
			// Inside a section or continuing a field.
			if strings.Contains(rawLine, ":") {
				// New field inside a section.
				flush()
				fieldName, fieldValue, _ := strings.Cut(rawLine, ":")
				fieldName = strings.TrimSpace(fieldName)
				fieldValue = strings.TrimSpace(fieldValue)
				collectingField = fieldName
				collectedValue.WriteString(fieldValue)
			} else if collectingField != "" {
				// Continuation of current field.
				collectedValue.WriteString(" ")
				collectedValue.WriteString(trimmed)
			}
		} else {
			// Top-level line.
			flush()
			if strings.Contains(rawLine, ":") {
				// Top-level field.
				fieldName, fieldValue, _ := strings.Cut(rawLine, ":")
				fieldName = strings.TrimSpace(fieldName)
				fieldValue = strings.TrimSpace(fieldValue)
				collectingField = fieldName
				collectedValue.WriteString(fieldValue)
			} else {
				// Section header (e.g., library, executable foo).
				collectingField = ""
			}
		}
	}
	flush()

	if err := s.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("error while scanning .cabal file: %w", err)
	}

	return inventory.Inventory{Packages: packages}, nil
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
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	// The package name is the first token (before any whitespace or operator).
	// Split on whitespace.
	idx := strings.IndexFunc(entry, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
	if idx < 0 {
		return entry
	}
	return entry[:idx]
}

var _ filesystem.Extractor = Extractor{}
