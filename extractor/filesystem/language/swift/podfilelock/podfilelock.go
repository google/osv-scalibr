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

// Package podfilelock extracts dependencies from Podfile.lock files.
package podfilelock

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/swift/swiftutils"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "swift/podfilelock"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Extractor extracts dependencies from Podfile.lock files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New creates a new instance of the Podfile.lock extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.SwiftPodfileLockConfig { return c.GetSwiftPodfileLock() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name returns the extractor's name.
func (e Extractor) Name() string { return Name }

// Version returns the extractor's version.
func (e Extractor) Version() int { return 0 }

// Requirements defines the extractor's capabilities.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired checks if a file is named Podfile.lock and meets size constraints.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "Podfile.lock" {
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

// Extract processes and extracts dependency information from a Podfile.lock file.
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
	packages, err := swiftutils.ParsePodfileLock(input.Reader)
	if err != nil {
		return nil, err
	}

	var result []*extractor.Package
	for _, pkg := range packages {
		result = append(result, &extractor.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			PURLType:  purl.TypeCocoapods,
			Locations: []string{input.Path},
		})
	}

	return result, nil
}
