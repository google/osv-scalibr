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
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/saferwall/pe"
)

const (
	// Name is the unique Name of this extractor.
	Name = "dotnet/pe"
)

// Supported extensions for Portable Executable (PE) files.
// This list may not be exhaustive, as the PE standard does not mandate specific extensions.
// The empty string is intentionally included to handle files without extensions.
var peExtensions = []string{
	".acm", ".ax", ".cpl", ".dll", ".drv", ".efi", ".exe", ".mui", ".ocx",
	".scr", ".sys", ".tsp", ".mun", ".msstyles", "",
}

// Extractor extracts dotnet dependencies from a PE file
type Extractor struct {
	cfg Config
}

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

// NewDefault returns the extractor with its default configuration.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS: plugin.OSWindows,
	}
}

// FileRequired returns true if the specified file matches the .NET PE file structure.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	// check if the file extension matches one of the known PE extensions
	ext := strings.ToLower(filepath.Ext(path))
	if !slices.Contains(peExtensions, ext) {
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

// Extract parses the PE files to extract .NET package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
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

func (e Extractor) extractFromInput(input *filesystem.ScanInput) (inventory.Inventory, error) {
	// check if the file has the needed magic bytes before doing the heavy parsing
	if ok, err := hasPEMagicBytes(input); !ok {
		return inventory.Inventory{}, fmt.Errorf("the file header does not contain magic bytes %w", err)
	}

	// Retrieve the real path of the file
	absPath, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, err
	}

	if input.Root == "" {
		// The file got copied to a temporary dir, remove it at the end.
		defer func() {
			dir := filepath.Base(absPath)
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("os.RemoveAll(%q): %v", dir, err)
			}
		}()
	}

	// Open the PE file
	f, err := pe.New(absPath, &pe.Options{})
	if err != nil {
		return inventory.Inventory{}, err
	}

	// Parse the PE file
	if err := f.Parse(); err != nil {
		return inventory.Inventory{}, err
	}

	// Initialize inventory slice to store the dependencies
	var pkgs []*extractor.Package

	// Iterate over the CLR Metadata Tables to extract assembly information
	for _, table := range f.CLR.MetadataTables {
		pkgs = append(pkgs, tableContentToPackages(f, table.Content)...)
	}

	// if at least an inventory was found inside the CLR.MetadataTables there is no need to check the VersionResources
	if len(pkgs) > 0 {
		return inventory.Inventory{Packages: pkgs}, nil
	}

	// If no inventory entries were found in CLR.MetadataTables check the VersionResources as a fallback
	// this is mostly required on .exe files
	versionResources, err := f.ParseVersionResources()
	if err != nil {
		return inventory.Inventory{}, err
	}

	name, version := versionResources["InternalName"], versionResources["Assembly Version"]
	if name != "" && version != "" {
		pkgs = append(pkgs, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeNuget,
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

func tableContentToPackages(f *pe.File, content any) []*extractor.Package {
	var pkgs []*extractor.Package

	switch content := content.(type) {
	case []pe.AssemblyTableRow:
		for _, row := range content {
			name := string(f.GetStringFromData(row.Name, f.CLR.MetadataStreams["#Strings"])) + ".dll"
			version := fmt.Sprintf("%d.%d.%d.%d", row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber)
			pkgs = append(pkgs, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeNuget,
			})
		}
	case []pe.AssemblyRefTableRow:
		for _, row := range content {
			name := string(f.GetStringFromData(row.Name, f.CLR.MetadataStreams["#Strings"])) + ".dll"
			version := fmt.Sprintf("%d.%d.%d.%d", row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber)
			pkgs = append(pkgs, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeNuget,
			})
		}
	}

	return pkgs
}

// hasPEMagicBytes checks if a given file has the PE magic bytes in the header
func hasPEMagicBytes(input *filesystem.ScanInput) (bool, error) {
	// check for the smallest PE size.
	if input.Info.Size() < pe.TinyPESize {
		return false, nil
	}

	var magic uint16
	if err := binary.Read(input.Reader, binary.LittleEndian, &magic); err != nil {
		return false, err
	}

	// Validate if the magic bytes match any of the expected PE signatures
	hasPESignature := magic == pe.ImageDOSSignature || magic == pe.ImageDOSZMSignature
	return hasPESignature, nil
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

var _ filesystem.Extractor = Extractor{}
