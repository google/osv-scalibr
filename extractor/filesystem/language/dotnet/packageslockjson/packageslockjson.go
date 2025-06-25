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

// Package packageslockjson extracts packages.lock.json files.
package packageslockjson

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "dotnet/packageslockjson"
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: 0,
	}
}

// Extractor extracts packages from inside a packages.lock.json.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a requirements.txt extractor.
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

// PackagesLockJSON represents the `packages.lock.json` file generated from
// running `dotnet restore --use-lock-file`.
// The schema path we care about is:
// "dependencies" -> target framework moniker -> package name -> package info
type PackagesLockJSON struct {
	Dependencies map[string]map[string]PackageInfo `json:"dependencies"`
}

// PackageInfo represents a single package's info, including its resolved
// version, and its dependencies
type PackageInfo struct {
	// Resolved is the resolved version for this dependency.
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is marked executable.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "packages.lock.json" {
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

// Extract returns a list of dependencies in a packages.lock.json file.
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
	p, err := Parse(input.Reader)
	if err != nil {
		return nil, err
	}
	var res []*extractor.Package
	for _, packages := range p.Dependencies {
		for pkgName, info := range packages {
			pkg := &extractor.Package{
				Name:     pkgName,
				Version:  info.Resolved,
				PURLType: purl.TypeNuget,
				Locations: []string{
					input.Path,
				},
			}
			res = append(res, pkg)
		}
	}

	return res, nil
}

// Parse returns a struct representing the structure of a .NET project's
// packages.lock.json file.
func Parse(r io.Reader) (PackagesLockJSON, error) {
	dec := json.NewDecoder(r)
	var p PackagesLockJSON
	if err := dec.Decode(&p); err != nil {
		return PackagesLockJSON{}, fmt.Errorf("failed to decode packages.lock.json file: %w", err)
	}

	return p, nil
}
