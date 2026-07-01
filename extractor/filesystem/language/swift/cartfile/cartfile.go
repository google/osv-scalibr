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

// Package cartfile extracts Cartfile dependencies.
package cartfile

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
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
	Name = "swift/cartfile"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

var (
	// cartfileLineRegexp matches lines in the format: <origin> "<identifier>" <version>
	cartfileLineRegexp = regexp.MustCompile(`^(github|git|binary)\s+"([^"]+)"(?:\s+(.+))?$`)
)

// Extractor extracts packages from Cartfile files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Cartfile extractor.
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

// FileRequired checks if the file is named "Cartfile".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "Cartfile" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
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

// Extract parses and extracts dependency data from a Cartfile.
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
	return parse(input.Reader, input.Path)
}

// parse reads and parses a Cartfile for package details.
func parse(r io.Reader, path string) ([]*extractor.Package, error) {
	packages := make([]*extractor.Package, 0)
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and full-line comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		matches := cartfileLineRegexp.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		origin := matches[1]
		identifier := matches[2]
		version := strings.TrimSpace(matches[3])
		// Strip surrounding quotes from version if present
		version = strings.Trim(version, `"`)

		if version == "" {
			continue
		}

		var name, purlType string

		switch origin {
		case "github":
			name = normalizeSwiftURL(identifier)
			purlType = purl.TypeSwift
		case "git":
			name = normalizeGitURL(identifier)
			purlType = purl.TypeSwift
		case "binary":
			// Skip binary dependencies - no standard PURL mapping
			continue
		}

		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purlType,
			Location: extractor.LocationFromPathAndLine(filepath.ToSlash(path), lineNum),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read Cartfile: %w", err)
	}

	return packages, nil
}

// normalizeGitURL extracts the package URL-style name from a Git URL.
func normalizeGitURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err == nil && u.Host != "" && u.Path != "" {
		path := strings.TrimPrefix(u.Path, "/")
		return normalizeSwiftURL(u.Host + "/" + path)
	}

	loc := strings.TrimPrefix(rawURL, "https://")
	loc = strings.TrimPrefix(loc, "http://")
	loc = strings.TrimPrefix(loc, "git://")
	loc = strings.TrimPrefix(loc, "ssh://")

	if idx := strings.Index(loc, ":"); idx != -1 {
		loc = loc[idx+1:]
	}
	loc = strings.TrimPrefix(loc, "/")
	return normalizeSwiftURL(loc)
}

func normalizeSwiftURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, ".git")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "git://")
	raw = strings.TrimPrefix(raw, "ssh://git@")
	raw = strings.TrimPrefix(raw, "git@")
	raw = strings.TrimPrefix(raw, "github.com:")
	if strings.Count(raw, "/") == 1 {
		raw = "github.com/" + raw
	}
	return raw
}
