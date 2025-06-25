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

// Copyright 2024 Google LLC
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

// Package packagesconfig extracts packages from .NET packages.config files.
package packagesconfig

import (
	"context"
	"encoding/xml"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "dotnet/packagesconfig"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 20 * units.MiB // 20 MB
)

// Config is the configuration for the .NET packages.config extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the .NET packages.config extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor structure for .NET packages.config files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a .NET packages.config extractor.
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
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches the .NET packages.config pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "packages.config" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil || (e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes) {
		e.reportFileRequired(path, stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:   path,
		Result: result,
	})
}

// Extract parses the packages.config file to extract .NET package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages, err := e.extractFromInput(input)
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
	return inventory.Inventory{Packages: packages}, err
}

type dotNETPackage struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

type dotNETPackages struct {
	XMLName  xml.Name        `xml:"packages"`
	Packages []dotNETPackage `xml:"package"`
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	var packages dotNETPackages
	decoder := xml.NewDecoder(input.Reader)
	if err := decoder.Decode(&packages); err != nil {
		log.Errorf("Error parsing packages.config: %v", err)
		return nil, err
	}

	var result []*extractor.Package
	for _, pkg := range packages.Packages {
		if pkg.ID == "" || pkg.Version == "" {
			log.Warnf("Skipping package with missing name or version: %+v", pkg)
			continue
		}

		result = append(result, &extractor.Package{
			Name:      pkg.ID,
			Version:   pkg.Version,
			PURLType:  purl.TypeNuget,
			Locations: []string{input.Path},
		})
	}

	return result, nil
}
