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

// Package portage extracts packages from portage database.
package portage

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	portagemeta "github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/portage"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

// Extractor extracts packages from Portage files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Portage extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.PortageConfig { return c.GetPortage() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches portage package database pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !fileRequired(path) {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > noLimitMaxFileSizeBytes && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func fileRequired(path string) bool {
	// Define Portage-specific file patterns here
	normalized := filepath.ToSlash(path)

	// Should only match PF files in /var/db/pkg/ directory
	return strings.HasPrefix(normalized, "var/db/pkg/") && strings.HasSuffix(normalized, "/PF")
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

// Extract extracts packages from portage database files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(input)
	if e.Stats == nil {
		return inventory.Inventory{Packages: pkgs}, err
	}
	var fileSizeBytes int64
	if input.Info != nil {
		fileSizeBytes = input.Info.Size()
	}
	e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          input.Path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	osRelease, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.GetOSRelease(): %v", err)
	}

	var pf string

	content, err := io.ReadAll(input.Reader)
	if err != nil {
		log.Errorf("unable to read file %s: %v", input.Path, err)
		return nil, err
	}

	pf = strings.TrimSpace(string(content))
	if pf == "" {
		log.Warnf("Portage PF File is empty (pf: %q)", pf)
	}

	pkgName, pkgVersion := splitPackageAndVersion(pf)
	if pkgName == "" || pkgVersion == "" {
		return nil, fmt.Errorf("no package name or version found in PF file: %s", pf)
	}

	p := &extractor.Package{
		Name:     pkgName,
		Version:  pkgVersion,
		PURLType: purl.TypePortage,
		Metadata: &portagemeta.Metadata{
			PackageName:    pkgName,
			PackageVersion: pkgVersion,
			OSID:           osRelease["ID"],
			OSVersionID:    osRelease["VERSION_ID"],
		},
		Locations: []string{input.Path},
	}

	return []*extractor.Package{p}, nil
}

func splitPackageAndVersion(path string) (string, string) {
	parts := strings.Split(path, "-") // Split the path by '-'
	var nameParts []string
	var versionParts []string

	for i, part := range parts {
		// Check if the part starts with a digit to identify version components
		if len(part) > 0 && unicode.IsDigit(rune(part[0])) {
			versionParts = parts[i:]
			nameParts = parts[:i]
			break
		}
	}

	// Reassemble the name and version parts
	packageName := strings.Join(nameParts, "-")
	packageVersion := strings.Join(versionParts, "-")

	return packageName, packageVersion
}
