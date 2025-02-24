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

// Package dotnetpe extracts packages from .NET PE files.
package dotnetpe

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	peparser "github.com/saferwall/pe"
)

const (
	// name is the unique name of this extractor.
	name = "dotnet/pe"
)

var (
	peExtensions = []string{
		".acm", ".ax", ".cpl", ".dll", ".drv", ".efi", ".exe", ".mui", ".ocx",
		".scr", ".sys", ".tsp", ".mun", ".msstyles", "",
	}

	ErrOpeningPEFile = errors.New("error opening PE file")
	ErrParsingPEFile = errors.New("error parsing PE file")
)

// Config is the configuration for the .NET PE extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will parse. If
	// `FileRequired` gets a bigger file, it will return false.
	// Use 0 to accept all file sizes
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration of the extractor.
func DefaultConfig() Config {
	return Config{}
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

// Extractor extracts dotnet dependencies from a PE file
type Extractor struct {
	cfg Config
}

// Ecosystem implements filesystem.Extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return "NuGet"
}

func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	inventory, err := e.extractFromInput(input)
	if e.cfg.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.cfg.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	// Retrieve the real path of the file
	realPath, err := input.GetRealPath()
	if err != nil {
		return nil, err
	}

	// Open the PE file
	pe, err := peparser.New(realPath, &peparser.Options{})
	if err != nil {
		return nil, errors.Join(ErrOpeningPEFile, err)
	}

	// Parse the PE file
	if err := pe.Parse(); err != nil {
		return nil, errors.Join(ErrParsingPEFile, err)
	}

	// Initialize inventory slice to store the dependencies
	var ivs []*extractor.Inventory

	// Iterate over the CLR Metadata Tables to extract assembly information
	for _, table := range pe.CLR.MetadataTables {
		switch content := table.Content.(type) {
		case []peparser.AssemblyTableRow:
			for _, row := range content {
				name := string(pe.GetStringFromData(row.Name, pe.CLR.MetadataStreams["#Strings"])) + ".dll"
				version := fmt.Sprintf("%d.%d.%d.%d", row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber)
				ivs = append(ivs, &extractor.Inventory{
					Name:    name,
					Version: version,
				})
			}
		case []peparser.AssemblyRefTableRow:
			for _, row := range content {
				name := string(pe.GetStringFromData(row.Name, pe.CLR.MetadataStreams["#Strings"])) + ".dll"
				version := fmt.Sprintf("%d.%d.%d.%d", row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber)
				ivs = append(ivs, &extractor.Inventory{
					Name:    name,
					Version: version,
				})
			}
		}
	}

	if len(ivs) > 0 {
		return ivs, nil
	}

	// If no inventory entries were found in CLR.MetadataTables check the VersionResources as a fallback
	if versionResources, err := pe.ParseVersionResources(); err == nil {
		name, version := versionResources["InternalName"], versionResources["Assembly Version"]
		if name != "" && version != "" {
			ivs = append(ivs, &extractor.Inventory{
				Name:    name,
				Version: version,
			})
		}
	}

	return ivs, nil
}

func isPE(path string) bool {
	ext := filepath.Ext(path)
	for _, peExt := range peExtensions {
		if strings.EqualFold(ext, peExt) {
			return true
		}
	}
	return false
}

// FileRequired returns true if the specified file matches the .NET PE file structure.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if !isPE(path) {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil || (e.cfg.MaxFileSizeBytes > 0 && fileinfo.Size() > e.cfg.MaxFileSizeBytes) {
		e.reportFileRequired(path, stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, stats.FileRequiredResultOK)
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
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{DirectFS: true}
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
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
