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
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dotnetpe extracts packages from .NET PE files.
package dotnetpe

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// name is the unique name of this extractor.
	name = "dotnet/pe"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 20 * units.MiB // 20 MB
)

// Config is the configuration for the .NET PE extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration of the extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// New returns an .NET PE extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		cfg: cfg,
	}
}

type Extractor struct {
	cfg Config
}

// Ecosystem implements filesystem.Extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	// TODO: check if this is correct
	return "NuGet"
}

// Extract parses the PE files to extract .NET package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	panic("unimplemented")
}

// FileRequired returns true if the specified file matches the .NET PE file structure.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	// TODO: add extensions matching
	if filepath.Base(path) != "" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil || (e.cfg.MaxFileSizeBytes > 0 && fileinfo.Size() > e.cfg.MaxFileSizeBytes) {
		e.reportFileRequired(path, stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	// TODO: add format matching (something simple to see if the file is pe)

	return true
}

func (e Extractor) reportFileRequired(path string, result stats.FileRequiredResult) {
	if e.cfg.Stats == nil {
		return
	}
	e.cfg.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:   path,
		Result: result,
	})
}

// Name of the extractor.
func (e Extractor) Name() string {
	return name
}

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		// TODO: check if this is correct
		Type:    purl.TypeNuget,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Version of the extractor.
func (e Extractor) Version() int {
	return 0
}

var _ filesystem.Extractor = Extractor{}
