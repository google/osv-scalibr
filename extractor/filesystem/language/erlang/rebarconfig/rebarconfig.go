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

// Package rebarconfig extracts Rebar3 dependency declarations from rebar.config manifests.
package rebarconfig

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
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
	Name = "erlang/rebarconfig"
)

var (
	// reDepTuple matches simple Erlang tuple forms: {Name, "Version"} or {Name, 'Version'}.
	reDepTuple = regexp.MustCompile(`\{([^,{}]+)\s*,\s*["']([^"']+)["']\s*\}`)
	// reDepTupleStart matches simple Erlang tuple forms at the start of a line.
	reDepTupleStart = regexp.MustCompile(`^\s*\{([^,{}]+)\s*,\s*["']([^"']+)["']\s*\}`)
	// reDepsStart matches the start of a deps block.
	reDepsStart = regexp.MustCompile(`\{deps\s*,`)
	// reDepsEnd matches the end of a deps list.
	reDepsEnd = regexp.MustCompile(`\]\s*\}?\.?\s*$`)
)

// skipNames are Erlang tuple names that should not be treated as dependencies.
var skipNames = map[string]bool{
	"tag": true, "ref": true, "branch": true, "commit": true, "rev": true,
	"pkg": true, "git": true, "hg": true, "bzr": true, "svn": true,
	"path": true, "file": true, "raw": true, "env": true,
}

// Extractor extracts Rebar3 dependency declarations from rebar.config files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches a rebar.config.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "rebar.config"
}

// Extract extracts Rebar3 dependency declarations from rebar.config files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	s := bufio.NewScanner(input.Reader)
	packages := make([]*extractor.Package, 0)
	lineNumber := 0
	state := "looking"
	bracketDepth := 0

	for s.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		rawLine := s.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		// Track bracket depth for quote-aware brace counting.
		stripped := stripComment(rawLine)
		bracketDepth += countChars(stripped, '{')
		bracketDepth -= countChars(stripped, '}')
		if bracketDepth < 0 {
			bracketDepth = 0
		}

		// Check for deps block start.
		if state == "looking" && reDepsStart.MatchString(line) {
			state = "inDeps"
		}

		// Extract deps if in deps list.
		if state == "inDeps" {
			pkgs := parseDepLine(line, input.Path, lineNumber)
			packages = append(packages, pkgs...)
		}

		// Check for deps block end after extraction.
		if state == "inDeps" && bracketDepth == 0 && reDepsEnd.MatchString(line) {
			state = "done"
		}
	}

	if err := s.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("error while scanning rebar.config: %w", err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

func stripComment(line string) string {
	if before, _, ok := strings.Cut(line, "%"); ok {
		return before
	}
	return line
}

func countChars(s string, ch byte) int {
	inSingleQuote := false
	inDoubleQuote := false
	count := 0
	for i := range len(s) {
		c := s[i]
		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
		} else if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
		} else if c == ch && !inSingleQuote && !inDoubleQuote {
			count++
		}
	}
	return count
}

func parseDepLine(line, path string, lineNumber int) []*extractor.Package {
	// Multi-line deps block: only match at the start of the line.
	match := reDepTupleStart.FindStringSubmatch(line)
	if match != nil {
		name := strings.TrimSpace(match[1])
		version := strings.TrimSpace(match[2])
		return []*extractor.Package{{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeHex,
			Location: extractor.LocationFromPathAndLine(path, lineNumber),
		}}
	}

	// Single-line deps block: find all tuples on the line.
	if !reDepsStart.MatchString(line) {
		return nil
	}

	matches := reDepTuple.FindAllStringSubmatch(line, -1)
	var packages []*extractor.Package
	for _, m := range matches {
		name := strings.TrimSpace(m[1])
		version := strings.TrimSpace(m[2])
		if skipNames[name] {
			continue
		}
		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeHex,
			Location: extractor.LocationFromPathAndLine(path, lineNumber),
		})
	}
	return packages
}

var _ filesystem.Extractor = Extractor{}
