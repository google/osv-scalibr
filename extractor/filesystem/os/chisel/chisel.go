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

// Package chisel extracts packages from chisel manifest.
package chisel

import (
	"context"
	"path/filepath"

	"github.com/canonical/chisel/public/jsonwall"
	"github.com/klauspost/compress/zstd"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/chisel"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB

	// packageMaintainer is maintainer's contact of the package.
	// For chiselled packages from Ubuntu archive, it is always Ubuntu Developers.
	packageMaintainer = "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"
)

type ChiselPackage struct {
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"sha256,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts packages from chisel manifest.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a chisel extractor.
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

// FileRequired returns true if the specified file matches chisel manifest file pattern.
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
	normalized := filepath.ToSlash(path)
	return normalized == "var/lib/chisel/manifest.wall"
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

// Extract extracts packages from the chisel manifest passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(ctx, input)
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

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	pkgs := []*extractor.Package{}

	manifest, err := zstd.NewReader(input.Reader)
	if err != nil {
		return pkgs, err
	}
	defer manifest.Close()

	db, err := jsonwall.ReadDB(manifest)
	if err != nil {
		return pkgs, err
	}

	packagesIterator, err := db.Iterate(&ChiselPackage{Kind: "package"})
	if err != nil {
		return pkgs, err
	}

	for packagesIterator.Next() {
		var chiselPackage ChiselPackage
		if err := packagesIterator.Get(&chiselPackage); err != nil {
			return pkgs, err
		}

		pkgName := chiselPackage.Name
		pkgVersion := chiselPackage.Version
		if pkgName == "" || pkgVersion == "" {
			log.Warnf("Package name or version is empty in chisel manifest (name: %q, version: %q)", pkgName, pkgVersion)
			continue
		}

		p := &extractor.Package{
			Name:    chiselPackage.Name,
			Version: pkgVersion,
			Metadata: &Metadata{
				PackageName:       pkgName,
				PackageVersion:    pkgVersion,
				OSID:              m["ID"],
				OSVersionCodename: m["VERSION_CODENAME"],
				OSVersionID:       m["VERSION_ID"],
				Maintainer:        packageMaintainer,
				Architecture:      chiselPackage.Arch,
			},
			Locations: []string{input.Path},
		}

		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func toNamespace(m *Metadata) string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'linux'")
	// TODO(b/298152210): Implement metric
	return "linux"
}

func toDistro(m *Metadata) string {
	// e.g. jammy
	if m.OSVersionCodename != "" {
		return m.OSVersionCodename
	}
	// fallback: e.g. 22.04
	if m.OSVersionID != "" {
		log.Warnf("VERSION_CODENAME not set in os-release, fallback to VERSION_ID")
		return m.OSVersionID
	}
	log.Errorf("VERSION_CODENAME and VERSION_ID not set in os-release")
	return ""
}

func (e Extractor) ToPURL(p *extractor.Package) *purl.PackageURL {
	m := p.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)
	if distro != "" {
		q[purl.Distro] = distro
	}
	if m.Architecture != "" {
		q[purl.Arch] = m.Architecture
	}

	return &purl.PackageURL{
		Type:       purl.TypeChisel,
		Name:       m.PackageName,
		Namespace:  toNamespace(m),
		Version:    p.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}
}

func (Extractor) Ecosystem(p *extractor.Package) string {
	m := p.Metadata.(*Metadata)
	osID := cases.Title(language.English).String(toNamespace(m))
	if m.OSVersionID == "" {
		return osID
	}
	return osID + ":" + m.OSVersionID
}
