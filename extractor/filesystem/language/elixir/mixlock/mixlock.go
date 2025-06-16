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

// Package mixlock extracts elixir mix.lock files.
package mixlock

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock/mixlockutils"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "elixir/mixlock"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB // 10 MB
)

// Config is the configuration for the Elixir extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the Elixir extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor structure for mix.lock files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns an Elixir extractor.
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

// FileRequired returns true if the specified file matches the mix.lock pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !(filepath.Base(path) == "mix.lock") {
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

// Extract parses the mix.lock file to extract Elixir package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := mixlockutils.ParseMixLockFile(input)
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
	return inv, err
}
