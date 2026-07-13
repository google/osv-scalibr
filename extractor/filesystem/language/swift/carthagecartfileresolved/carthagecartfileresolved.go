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

// Package carthagecartfileresolved extracts Carthage Cartfile.resolved dependencies.
package carthagecartfileresolved

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
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
	Name = "swift/carthagecartfileresolved"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Extractor extracts packages from a Carthage Cartfile.resolved file.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Cartfile.resolved extractor.
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

// FileRequired checks if the file is named "Cartfile.resolved".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "Cartfile.resolved" {
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

// Extract parses and extracts dependency data from a Cartfile.resolved file.
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
	packages, err := parse(input.Reader)
	if err != nil {
		return nil, err
	}

	result := make([]*extractor.Package, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, &extractor.Package{
			Name:     pkg.Name,
			Version:  pkg.Version,
			PURLType: pkg.PURLType,
			Location: extractor.LocationFromPathAndLine(input.Path, pkg.Line),
		})
	}

	return result, nil
}

// pkg represents a parsed package entry from the Cartfile.resolved file.
type pkg struct {
	Name     string
	Version  string
	PURLType string
	Line     int
}

// parse reads and parses a Cartfile.resolved file for package details.
// Format: <origin> "<identifier>" "<version>"
// Origins: github, git, binary (binary entries are skipped).
func parse(r io.Reader) ([]pkg, error) {
	packages := []pkg{}
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid line %d: expected at least 3 fields, got %d", lineNum, len(parts))
		}

		origin := parts[0]
		identifier, err := unquote(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid line %d: %w", lineNum, err)
		}
		version, err := unquote(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid line %d: %w", lineNum, err)
		}

		if identifier == "" || version == "" {
			return nil, fmt.Errorf("invalid line %d: empty identifier or version", lineNum)
		}

		switch origin {
		case "github":
			packages = append(packages, pkg{
				Name:     normalizeSwiftURL(identifier),
				Version:  version,
				PURLType: purl.TypeSwift,
				Line:     lineNum,
			})
		case "git":
			name := normalizeGitURL(identifier)
			packages = append(packages, pkg{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeSwift,
				Line:     lineNum,
			})
		case "binary":
			// Skip binary entries: they don't map to standard PURL types.
			continue
		default:
			return nil, fmt.Errorf("invalid line %d: unknown origin %q", lineNum, origin)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read Cartfile.resolved: %w", err)
	}

	return packages, nil
}

// unquote removes leading and trailing quotes from a Cartfile.resolved field.
func unquote(s string) (string, error) {
	u, err := strconv.Unquote(s)
	if err != nil {
		return "", err
	}
	return u, nil
}

// normalizeGitURL extracts the path from a Git URL to use as the package name.
// It strips the scheme and .git suffix if present.
func normalizeGitURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err == nil && u.Host != "" && u.Path != "" {
		path := strings.TrimPrefix(u.Path, "/")
		return normalizeSwiftURL(u.Host + "/" + path)
	}

	// Fallback: manual stripping if URL parsing fails.
	loc := strings.TrimPrefix(rawURL, "https://")
	loc = strings.TrimPrefix(loc, "http://")
	loc = strings.TrimPrefix(loc, "git://")
	loc = strings.TrimPrefix(loc, "ssh://")

	// Remove user@host:path syntax.
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
