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

// Package cpanfile extracts CPAN dependency declarations from cpanfile manifests.
package cpanfile

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
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
	Name = "perl/cpanfile"
)

var (
	// reSingleQuoteDep matches dependency declarations using single quotes.
	reSingleQuoteDep = regexp.MustCompile(`^\s*(requires|test_requires|configure_requires|build_requires|recommends|suggests)\s+'([^']+)'(?:\s*,\s*'([^']+)')?\s*;`)
	// reDoubleQuoteDep matches dependency declarations using double quotes.
	reDoubleQuoteDep = regexp.MustCompile(`^\s*(requires|test_requires|configure_requires|build_requires|recommends|suggests)\s+"([^"]+)"(?:\s*,\s*"([^"]+)")?\s*;`)
)

// Extractor extracts CPAN dependency declarations from cpanfile manifests.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches a cpanfile.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "cpanfile"
}

// Extract extracts CPAN dependency declarations from cpanfile files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	s := bufio.NewScanner(input.Reader)
	packages := make([]*extractor.Package, 0)
	lineNumber := 0
	blockDepth := 0

	for s.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		rawLine := s.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip comments for brace counting.
		stripped := stripComment(rawLine)
		// Track block depth to skip dynamic blocks (sub, on, if, feature, etc.).
		blockDepth += countBraces(stripped, '{')
		blockDepth -= countBraces(stripped, '}')
		if blockDepth < 0 {
			blockDepth = 0
		}
		if blockDepth > 0 {
			continue
		}
		// Skip lines that start with block keywords.
		if isBlockStart(line) {
			continue
		}

		pkg := parseLine(line, input.Path, lineNumber)
		if pkg != nil {
			packages = append(packages, pkg)
		}
	}

	if err := s.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("error while scanning cpanfile: %w", err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

func stripComment(line string) string {
	if before, _, ok := strings.Cut(line, "#"); ok {
		return before
	}
	return line
}

func countBraces(s string, ch byte) int {
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

func isBlockStart(line string) bool {
	keywords := []string{"sub", "on", "if", "unless", "while", "for", "foreach", "feature"}
	lower := strings.ToLower(line)
	for _, kw := range keywords {
		if strings.HasPrefix(lower, kw) {
			return true
		}
	}
	return false
}

func parseLine(line, path string, lineNumber int) *extractor.Package {
	var match []string
	if m := reSingleQuoteDep.FindStringSubmatch(line); m != nil {
		match = m
	} else if m := reDoubleQuoteDep.FindStringSubmatch(line); m != nil {
		match = m
	} else {
		return nil
	}

	depType := match[1]
	moduleName := match[2]
	version := ""
	if len(match) > 3 && match[3] != "" {
		version = match[3]
	}

	pkg := &extractor.Package{
		Name:     moduleName,
		Version:  version,
		PURLType: purl.TypeCPAN,
		Location: extractor.LocationFromPathAndLine(path, lineNumber),
	}

	switch depType {
	case "test_requires":
		pkg.Metadata = &osv.DepGroupMetadata{DepGroupVals: []string{"test"}}
	case "configure_requires":
		pkg.Metadata = &osv.DepGroupMetadata{DepGroupVals: []string{"configure"}}
	case "build_requires":
		pkg.Metadata = &osv.DepGroupMetadata{DepGroupVals: []string{"build"}}
	case "recommends":
		pkg.Metadata = &osv.DepGroupMetadata{DepGroupVals: []string{"recommends"}}
	case "suggests":
		pkg.Metadata = &osv.DepGroupMetadata{DepGroupVals: []string{"suggests"}}
	}

	return pkg
}

var _ filesystem.Extractor = Extractor{}
