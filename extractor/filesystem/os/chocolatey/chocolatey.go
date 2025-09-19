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

// Package chocolatey extracts installed binaries from .nuspec files.
package chocolatey

import (
	"context"
	"encoding/xml"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	chocolateymeta "github.com/google/osv-scalibr/extractor/filesystem/os/chocolatey/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/chocolatey"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

// ChocoModule xml parser struct for .nuspec file
type ChocoModule struct {
	XMLName  xml.Name `xml:"package"`
	Metadata Metadata `xml:"metadata"`
}

// Metadata xml parser struct for metadata tag inside .nuspec file
type Metadata struct {
	ID         string `xml:"id"`
	Version    string `xml:"version"`
	Authors    string `xml:"authors"`
	Summary    string `xml:"summary"`
	LicenseURL string `xml:"licenseUrl"`
	ProjectURL string `xml:"projectUrl"`
	Tags       string `xml:"tags"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the chocolatey extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts chocolatey packages from .nuspec file.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a chocolatey extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

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
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSWindows}
}

// FileRequired returns true if the specified file matches .nuspec file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	normalized := filepath.ToSlash(path)
	// Example: C:\ProgramData\chocolatey\lib\vscode\vscode.nuspec
	if !strings.Contains(normalized, "chocolatey/lib/") {
		return false
	}
	if !strings.HasSuffix(normalized, ".nuspec") {
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

// Extract extracts chocolatey info from .nuspec files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(input)
	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	var module ChocoModule
	packages := []*extractor.Package{}
	decoder := xml.NewDecoder(input.Reader)
	if err := decoder.Decode(&module); err != nil {
		log.Errorf("Error parsing nuspec file: %v", err)
		return nil, err
	}
	if module.Metadata.ID != "" && module.Metadata.Version != "" {
		p := &extractor.Package{
			Name:     module.Metadata.ID,
			Version:  module.Metadata.Version,
			PURLType: purl.TypeChocolatey,
			Metadata: &chocolateymeta.Metadata{
				Name:       module.Metadata.ID,
				Version:    module.Metadata.Version,
				Authors:    module.Metadata.Authors,
				Summary:    module.Metadata.Summary,
				LicenseURL: module.Metadata.LicenseURL,
				ProjectURL: module.Metadata.ProjectURL,
				Tags:       module.Metadata.Tags,
			},
			Locations: []string{input.Path},
		}
		packages = append(packages, p)
	}
	return packages, nil
}
