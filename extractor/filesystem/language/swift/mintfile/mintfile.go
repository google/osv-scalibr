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

// Package mintfile extracts dependencies from Mintfile files.
package mintfile

import (
	"bufio"
	"context"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "swift/mintfile"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Extractor extracts dependencies from Mintfile files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New creates a new instance of the Mintfile extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name returns the extractor's name.
func (e Extractor) Name() string { return Name }

// Version returns the extractor's version.
func (e Extractor) Version() int { return 0 }

// Requirements defines the extractor's capabilities.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired checks if a file is named Mintfile and meets size constraints.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "Mintfile" {
		return false
	}

	fileInfo, err := api.Stat()
	if err != nil {
		return false
	}

	if e.maxFileSizeBytes > 0 && fileInfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileInfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileInfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract processes and extracts dependency information from a Mintfile file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(input)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	scanner := bufio.NewScanner(input.Reader)
	var packages []*extractor.Package
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(stripComment(scanner.Text()))
		// Skip empty lines and comments.
		if line == "" {
			continue
		}

		name, version := parseLine(line)
		if name == "" {
			continue
		}

		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeSwift,
			Location: extractor.LocationFromPathAndLine(input.Path, lineNum),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

func stripComment(line string) string {
	before, _, _ := strings.Cut(line, "#")
	return before
}

// parseLine parses a single Mintfile line into package name and version.
// Format: owner/repo@version or owner/repo
func parseLine(line string) (name, version string) {
	if strings.Contains(line, "@") {
		parts := strings.SplitN(line, "@", 2)
		name = strings.TrimSpace(parts[0])
		version = strings.TrimSpace(parts[1])
	} else {
		name = strings.TrimSpace(line)
	}
	return normalizeSwiftPackageName(name), version
}

func normalizeSwiftPackageName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".git")
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimPrefix(name, "git://")
	name = strings.TrimPrefix(name, "ssh://git@")
	name = strings.TrimPrefix(name, "git@")
	name = strings.TrimPrefix(name, "github.com:")
	if strings.Count(name, "/") == 1 {
		name = "github.com/" + name
	}
	if strings.Count(name, "/") < 2 {
		return ""
	}
	return name
}
