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

// Package nix extracts packages from the Nix store directory.
package nix

import (
	"context"
	"fmt"
	"regexp"
	"strings"

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
	Name = "os/nix"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

var (
	// visitedDir tracks already visited directories.
	visitedDir = make(map[string]bool)
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the Nix extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts packages from the nix store directory.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a nix extractor.
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

// FileRequired returns true if a given path corresponds to a unique, unprocessed directory under the nixStoreDir path.
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
	// nixStoreDir is the standard location of the Nix store.
	nixStoreDir := "nix/store/"

	if strings.HasPrefix(path, nixStoreDir) {
		// e.g.
		// path: nix/store/1ddf3x30m0z6kknmrmapsc7liz8npi1w-perl-5.38.2/bin/ptar
		// pathParts: 1ddf3x30m0z6kknmrmapsc7liz8npi1w-perl-5.38.2
		pathParts := strings.Split(path, "/")

		if len(pathParts) > 3 {
			uniquePath := pathParts[2]

			// Check if uniquePath has been already processed. Scalibr scans through files but the info
			// about the nix packages are saved in the directory name.
			if _, exists := visitedDir[uniquePath]; !exists {
				visitedDir[uniquePath] = true
				return true
			}
		}
	}
	return false
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

// Extract extracts packages from the filenames of the directories in the nix store path.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	inventory, err := e.extractFromInput(ctx, input)

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

	return inventory, err
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var matches []string
	// packageStoreRegex implements the regex for the /nix/store pattern.
	packageStoreRegex := regexp.MustCompile(`^([a-zA-Z0-9]{32})-([a-zA-Z0-9.-]+)-([0-9.]+)(?:-(\S+))?$`)
	packageStoreUnstableRegex := regexp.MustCompile(`^([a-zA-Z0-9]{32})-([a-zA-Z0-9.-]+)-(unstable-[0-9]{4}-[0-9]{2}-[0-9]{2})$`)

	pkgs := []*extractor.Inventory{}

	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.GetOSRelease(): %v", err)
	}

	// Return if canceled or exceeding deadline.
	if err := ctx.Err(); err != nil {
		return pkgs, fmt.Errorf("%s halted at %q because of context error: %v", e.Name(), input.Path, err)
	}

	// e.g.
	// pkg = nix/store/mccadsxm3sgrcx2z0b9c8d5wgnlg7a3z-libarchive-3.7.4-lib/lib/libarchive.so.13.7.4
	// matches = [mccadsxm3sgrcx2z0b9c8d5wgnlg7a3z-libarchive-3.7.4-lib mccadsxm3sgrcx2z0b9c8d5wgnlg7a3z libarchive 3.7.4 lib]
	pkg := strings.Split(input.Path, "/")[2]

	// Handle unstable packages
	if !strings.Contains(pkg, "unstable") {
		matches = packageStoreRegex.FindStringSubmatch(pkg)
	} else {
		matches = packageStoreUnstableRegex.FindStringSubmatch(pkg)
	}

	if len(matches) != 0 {
		pkgHash := matches[1]
		pkgName := matches[2]
		pkgVersion := matches[3]

		if pkgHash != "" && pkgName != "" && pkgVersion != "" {
			i := &extractor.Inventory{
				Name:    pkgName,
				Version: pkgVersion,
				Metadata: &Metadata{
					PackageName:       pkgName,
					PackageVersion:    pkgVersion,
					PackageHash:       pkgHash,
					OSID:              m["ID"],
					OSVersionCodename: m["VERSION_CODENAME"],
					OSVersionID:       m["VERSION_ID"],
				},
				Locations: []string{input.Path},
			}

			if len(matches) > 4 {
				pkgOutput := matches[4]
				i.Metadata.(*Metadata).PackageOutput = pkgOutput
			}

			pkgs = append(pkgs, i)
		}
	}

	return pkgs, nil
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
		Type:       purl.TypeNix,
		Name:       i.Name,
		Version:    i.Version,
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

func toNamespace(m *Metadata) string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'nixos'")
	return "nixos"
}

func toDistro(m *Metadata) string {
	if m.OSVersionCodename != "" {
		return m.OSVersionCodename
	}

	if m.OSVersionID != "" {
		return m.OSVersionID
	}

	log.Errorf("VERSION_CODENAME and VERSION_ID not set in os-release")

	return ""
}