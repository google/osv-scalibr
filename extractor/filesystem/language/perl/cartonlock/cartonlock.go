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

// Package cartonlock extracts Perl CPAN dependencies from Carton cpanfile.snapshot lockfiles.
package cartonlock

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "perl/cartonlock"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Extractor extracts Perl CPAN dependencies from Carton cpanfile.snapshot files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a new instance of the extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches a cpanfile.snapshot.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	if filepath.Base(api.Path()) != "cpanfile.snapshot" {
		return false
	}
	fileinfo, err := api.Stat()
	return err == nil && (e.maxFileSizeBytes <= 0 || fileinfo.Size() <= e.maxFileSizeBytes)
}

// Extract extracts Perl CPAN dependencies from cpanfile.snapshot files.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	s := bufio.NewScanner(input.Reader)
	packages := make([]*extractor.Package, 0)

	inProvides := false
	for lineNumber := 1; s.Scan(); lineNumber++ {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		line := s.Text()
		// Skip blank lines and comment lines.
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// Indentation-based parsing.
		indent := countLeadingSpaces(line)
		trimmed := strings.TrimSpace(line)

		if indent == 4 && trimmed == "provides:" {
			inProvides = true
			continue
		}

		if indent <= 4 {
			// Exited the provides section (new sub-header or distribution).
			inProvides = false
			continue
		}

		if inProvides && indent >= 6 {
			pkg := parseProvidesEntry(trimmed, input.Path, lineNumber)
			if pkg != nil {
				packages = append(packages, pkg)
			}
		}
	}

	if err := s.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("error while scanning cpanfile.snapshot: %w", err)
	}

	return inventory.Inventory{Packages: packages}, nil
}

func countLeadingSpaces(s string) int {
	count := 0
	for _, c := range s {
		if c == ' ' {
			count++
		} else {
			break
		}
	}
	return count
}

func parseProvidesEntry(line, path string, lineNumber int) *extractor.Package {
	// Format: "Module::Name version" or "Module::Name undef"
	// The module name is everything before the last space.
	// The version is the last token.
	idx := strings.LastIndex(line, " ")
	if idx < 0 {
		return nil
	}
	name := strings.TrimSpace(line[:idx])
	version := strings.TrimSpace(line[idx+1:])
	if name == "" {
		return nil
	}
	// Skip placeholder versions (undef, 0) that indicate core modules or missing info.
	if version == "undef" || version == "0" {
		return nil
	}
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeCPAN,
		Location: extractor.LocationFromPathAndLine(path, lineNumber),
	}
}

var _ filesystem.Extractor = Extractor{}
