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
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/portage"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the Portage extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts packages from Portage files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Portage extractor.
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
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
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
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from portage database files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	inventory, err := e.extractFromInput(ctx, input)
	if e.stats == nil {
		return inventory, err
	}
	var fileSizeBytes int64
	if input.Info != nil {
		fileSizeBytes = input.Info.Size()
	}
	e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          input.Path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
	return inventory, err
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
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

	i := &extractor.Inventory{
		Name:    pkgName,
		Version: pkgVersion,
		Metadata: &Metadata{
			PackageName:    pkgName,
			PackageVersion: pkgVersion,
			OSID:           osRelease["ID"],
			OSVersionID:    osRelease["VERSION_ID"],
		},
		Locations: []string{input.Path},
	}

	return []*extractor.Inventory{i}, nil
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

func toNamespace(m *Metadata) string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'linux'")
	return "linux"
}

func toDistro(m *Metadata) string {
	if m.OSVersionID != "" {
		return m.OSVersionID
	}
	log.Errorf("VERSION_ID not set in os-release")
	return ""
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	m := i.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)
	if distro != "" {
		q[purl.Distro] = distro
	}
	return &purl.PackageURL{
		Type:       purl.TypePortage,
		Name:       m.PackageName,
		Version:    m.PackageVersion,
		Namespace:  toNamespace(m),
		Qualifiers: purl.QualifiersFromMap(q),
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) string {
	m := i.Metadata.(*Metadata)
	osID := cases.Title(language.English).String(toNamespace(m))
	if m.OSVersionID == "" {
		return osID
	}
	return osID + ":" + m.OSVersionID
}
