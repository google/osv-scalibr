// Copyright 2025 Google LLC
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

// Package plugins extracts packages from installed Wordpress plugins.
package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "wordpress/plugins"
)

// Config is the configuration for the Wordpress extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the Wordpress extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: 10 * units.MiB,
	}
}

// Extractor structure for plugins files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Wordpress extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor {
	return New(DefaultConfig())
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		Stats:            e.stats,
		MaxFileSizeBytes: e.maxFileSizeBytes,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches the /wp-content/plugins/ pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !strings.HasSuffix(path, ".php") || !strings.Contains(path, "wp-content/plugins/") {
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
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract parses the PHP file to extract Wordpress package.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkg, err := parsePHPFile(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	if pkg == nil {
		return inventory.Inventory{}, nil
	}

	return inventory.Inventory{Packages: []*extractor.Package{&extractor.Package{
		Name:      pkg.Name,
		Version:   pkg.Version,
		PURLType:  purl.TypeWordpress,
		Locations: []string{input.Path},
	}}}, nil
}

type wpPackage struct {
	Name    string
	Version string
}

func parsePHPFile(r io.Reader) (*wpPackage, error) {
	scanner := bufio.NewScanner(r)
	var name, version string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Plugin Name:") {
			name = strings.TrimSpace(strings.Split(line, "Plugin Name:")[1])
		}

		if strings.Contains(line, "Version:") {
			version = strings.TrimSpace(strings.Split(line, ":")[1])
		}

		if name != "" && version != "" {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read PHP file: %w", err)
	}

	if name == "" || version == "" {
		return nil, nil
	}

	return &wpPackage{Name: name, Version: version}, nil
}
