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

// Package depsjson extracts packages from .NET deps.json files.
package depsjson

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "dotnet/depsjson"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB // 10 MB
)

// Config is the configuration for the deps.json extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false.
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the deps.json extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor structure for deps.json files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a deps.json extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
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

// FileRequired returns true if the specified file matches the deps.json pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !strings.HasSuffix(path, ".deps.json") {
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

// Extract parses the deps.json file to extract .NET package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	packages, err := e.extractFromInput(ctx, input)
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
	return packages, err
}

// DepsJSON represents the structure of the deps.json file.
type DepsJSON struct {
	// Note: Libraries does not include transitive dependencies.
	// Targets is not currently extracted because it introduces significant
	// complexity and is not always necessary for basic dependency analysis.
	Libraries map[string]struct {
		Version string `json:"version"`
		// Type represents the package type, if present. Examples of types include:
		// - "package": Indicates a standard NuGet package dependency.
		// - "project": Represents a project-level dependency, such as the main application or a locally developed library.
		Type string `json:"type"`
	} `json:"libraries"`
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var deps DepsJSON
	decoder := json.NewDecoder(input.Reader)
	if err := decoder.Decode(&deps); err != nil {
		log.Errorf("Error parsing deps.json: %v", err)
		return nil, err
	}

	var inventories []*extractor.Inventory
	for nameVersion, library := range deps.Libraries {
		// Split name and version from "package/version" format
		name, version := splitNameAndVersion(nameVersion)
		if name == "" || version == "" {
			log.Warnf("Skipping library with missing name or version: %s", nameVersion)
			continue
		}
		// If the library type is "project", this is the root/main package.
		i := &extractor.Inventory{
			Name:    name,
			Version: version,
			Metadata: &Metadata{
				PackageName:    name,
				PackageVersion: version,
				Type:           library.Type,
			},
			Locations: []string{input.Path},
		}
		inventories = append(inventories, i)
	}

	return inventories, nil
}

// splitNameAndVersion splits the name and version from a "package/version" string.
func splitNameAndVersion(nameVersion string) (string, string) {
	parts := strings.Split(nameVersion, "/")
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeNuget,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) string {
	return "NuGet"
}
