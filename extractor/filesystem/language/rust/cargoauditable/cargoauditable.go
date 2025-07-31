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

// Package cargoauditable extracts dependencies from cargo auditable inside rust binaries.
package cargoauditable

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/rust-secure-code/go-rustaudit"
)

const (
	// Name is the unique name of this extractor.
	Name = "rust/cargoauditable"
)

// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
// If Extract gets a bigger file, it will return an error.
const defaultMaxFileSizeBytes = 0

// defaultExtractBuildDependencies is whether to extract build dependencies or only runtime ones.
const defaultExtractBuildDependencies = false

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum size of a file that can be extracted.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored by returning false for `FileRequired`.
	MaxFileSizeBytes int64
	// ExtractBuildDependencies is whether to extract build dependencies or only runtime ones.
	ExtractBuildDependencies bool
}

// Extractor for extracting dependencies from cargo auditable inside rust binaries.
type Extractor struct {
	stats                    stats.Collector
	maxFileSizeBytes         int64
	extractBuildDependencies bool
}

// DefaultConfig returns a default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:                    nil,
		MaxFileSizeBytes:         defaultMaxFileSizeBytes,
		ExtractBuildDependencies: defaultExtractBuildDependencies,
	}
}

// New returns a Cargo Auditable extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:                    cfg.Stats,
		maxFileSizeBytes:         cfg.MaxFileSizeBytes,
		extractBuildDependencies: cfg.ExtractBuildDependencies,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements for enabling the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is marked executable.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}

	if !filesystem.IsInterestingExecutable(api) {
		return false
	}

	sizeLimitExceeded := e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes
	result := stats.FileRequiredResultOK
	if sizeLimitExceeded {
		result = stats.FileRequiredResultSizeLimitExceeded
	}

	if e.stats != nil {
		e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
			Path:          path,
			Result:        result,
			FileSizeBytes: fileinfo.Size(),
		})
	}
	return !sizeLimitExceeded
}

// Extract extracts packages from cargo auditable inside rust binaries.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	reader, ok := input.Reader.(io.ReaderAt)
	if !ok {
		return inventory.Inventory{}, errors.New("input.Reader is not a ReaderAt")
	}

	dependencyInfo, err := rustaudit.GetDependencyInfo(reader)
	e.reportFileExtracted(input, filesystem.ExtractorErrorToFileExtractedResult(err))
	// Most errors are just that the file is not a cargo auditable rust binary.
	if err != nil {
		if errors.Is(err, rustaudit.ErrUnknownFileFormat) || errors.Is(err, rustaudit.ErrNoRustDepInfo) {
			return inventory.Inventory{}, nil
		}
		log.Debugf("error getting dependency information from binary (%s) for extraction: %v", input.Path, err)
		return inventory.Inventory{}, fmt.Errorf("rustaudit.GetDependencyInfo: %w", err)
	}

	pkgs := []*extractor.Package{}
	for _, dep := range dependencyInfo.Packages {
		// Cargo auditable also tracks build-only dependencies which we may not want to report.
		// Note: the main package is reported as a runtime dependency.
		if dep.Kind == rustaudit.Runtime || e.extractBuildDependencies {
			pkgs = append(pkgs, &extractor.Package{
				Name:      dep.Name,
				Version:   dep.Version,
				PURLType:  purl.TypeCargo,
				Locations: []string{input.Path},
			})
		}
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) reportFileExtracted(input *filesystem.ScanInput, result stats.FileExtractedResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          input.Path,
		Result:        result,
		FileSizeBytes: input.Info.Size(),
	})
}

// Ensure Extractor implements the filesystem.Extractor interface.
var _ filesystem.Extractor = Extractor{}
