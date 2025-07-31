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

// Package dpkg extracts packages from dpkg database.
package dpkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/dpkg"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB

	// defaultIncludeNotInstalled is the default value for the IncludeNotInstalled option.
	defaultIncludeNotInstalled = false
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
	// IncludeNotInstalled includes packages that are not installed
	// (e.g. `deinstall`, `purge`, and those missing a status field).
	IncludeNotInstalled bool
}

// DefaultConfig returns the default configuration for the DPKG extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes:    defaultMaxFileSizeBytes,
		IncludeNotInstalled: defaultIncludeNotInstalled,
	}
}

// Extractor extracts packages from DPKG files.
type Extractor struct {
	stats               stats.Collector
	maxFileSizeBytes    int64
	includeNotInstalled bool
}

// New returns a DPKG extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:               cfg.Stats,
		maxFileSizeBytes:    cfg.MaxFileSizeBytes,
		includeNotInstalled: cfg.IncludeNotInstalled,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		Stats:               e.stats,
		MaxFileSizeBytes:    e.maxFileSizeBytes,
		IncludeNotInstalled: e.includeNotInstalled,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches dpkg status file pattern.
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

	// Normal status file matching DPKG or OPKG format
	if normalized == "var/lib/dpkg/status" || normalized == "usr/lib/opkg/status" {
		return true
	}

	// Should only match status files in status.d directory.
	return strings.HasPrefix(normalized, "var/lib/dpkg/status.d/") && !strings.HasSuffix(normalized, ".md5sums")
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

// Extract extracts packages from dpkg status files passed through the scan input.
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

	rd := textproto.NewReader(bufio.NewReader(input.Reader))
	pkgs := []*extractor.Package{}
	for eof := false; !eof; {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return pkgs, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		h, err := rd.ReadMIMEHeader()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// We might still have one more line of data
				// so return only after it's been parsed.
				eof = true
			} else {
				if strings.Contains(input.Path, "status.d") {
					log.Warnf("Failed to read MIME header from %q: %v", input.Path, err)
					return []*extractor.Package{}, nil
				}
				return pkgs, err
			}
		}

		// Skip empty lines
		if len(h) == 0 {
			continue
		}

		// Distroless distributions have their packages in status.d, which does not contain the Status
		// value.
		if !e.includeNotInstalled && (!strings.Contains(input.Path, "status.d") || h.Get("Status") != "") {
			if h.Get("Status") == "" {
				log.Warnf("Package %q has no status field", h.Get("Package"))
				continue
			}
			installed, err := statusInstalled(h.Get("Status"))
			if err != nil {
				return pkgs, fmt.Errorf("statusInstalled(%q): %w", h.Get("Status"), err)
			}
			if !installed {
				continue
			}
		}

		pkgName := h.Get("Package")
		pkgVersion := h.Get("Version")
		if pkgName == "" || pkgVersion == "" {
			if !eof { // Expected when reaching the last line.
				log.Warnf("DPKG package name or version is empty (name: %q, version: %q)", pkgName, pkgVersion)
			}
			continue
		}

		description := strings.ToLower(h.Get("Description"))
		var annotations []extractor.Annotation
		var vexes []*vex.PackageExploitabilitySignal
		if strings.Contains(description, "transitional package") ||
			strings.Contains(description, "transitional dummy package") ||
			strings.Contains(description, "transitional empty package") {
			annotations = append(annotations, extractor.Transitional)
			vexes = append(vexes, &vex.PackageExploitabilitySignal{
				Plugin:          Name,
				Justification:   vex.ComponentNotPresent,
				MatchesAllVulns: true,
			})
		}

		purlType := purl.TypeDebian
		if input.Path == "usr/lib/opkg/status" {
			purlType = purl.TypeOpkg
		}

		p := &extractor.Package{
			Name:     pkgName,
			Version:  pkgVersion,
			PURLType: purlType,
			Metadata: &dpkgmeta.Metadata{
				PackageName:       pkgName,
				PackageVersion:    pkgVersion,
				Status:            h.Get("Status"),
				OSID:              m["ID"],
				OSVersionCodename: m["VERSION_CODENAME"],
				OSVersionID:       m["VERSION_ID"],
				Maintainer:        h.Get("Maintainer"),
				Architecture:      h.Get("Architecture"),
			},
			Locations: []string{input.Path},
			// TODO(b/400910349): Remove once integrators stop using annotations.
			AnnotationsDeprecated: annotations,
			ExploitabilitySignals: vexes,
		}
		sourceName, sourceVersion, err := parseSourceNameVersion(h.Get("Source"))
		if err != nil {
			return pkgs, fmt.Errorf("parseSourceNameVersion(%q): %w", h.Get("Source"), err)
		}
		if sourceName != "" {
			p.Metadata.(*dpkgmeta.Metadata).SourceName = sourceName
			p.Metadata.(*dpkgmeta.Metadata).SourceVersion = sourceVersion
		}

		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func statusInstalled(status string) (bool, error) {
	// Status field format: "want flag status", e.g. "install ok installed"
	// The package is currently installed if the status field is set to installed.
	// Other fields just show the intent of the package manager but not the current state.
	parts := strings.Split(status, " ")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid DPKG Status field %q", status)
	}
	return parts[2] == "installed", nil
}

func parseSourceNameVersion(source string) (string, string, error) {
	if source == "" {
		return "", "", nil
	}
	// Format is either "name" or "name (version)"
	if idx := strings.Index(source, " ("); idx != -1 {
		if !strings.HasSuffix(source, ")") {
			return "", "", fmt.Errorf("invalid DPKG Source field: %q", source)
		}
		n := source[:idx]
		v := source[idx+2 : len(source)-1]
		return n, v, nil
	}
	return source, "", nil
}
