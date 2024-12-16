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

// Package pacmna extracts packages from archlinux desc file.
package pacman

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
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
	Name = "os/pacman"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the pacman extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts pacman packages from /var/lib/pacman/local/<package>/desc file.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a pacman extractor.
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

// FileRequired returns true if the specified file matches the "desc" file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	// archPrefix and archSuffix are used to match the right file and location.
	archPrefix := "var/lib/pacman/local/"
	archSuffix := "desc"
	path := api.Path()

	if !strings.HasPrefix(path, archPrefix) || filepath.Base(path) != archSuffix {
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

// Extract extracts packages from "desc" files passed through the scan input.
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
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	s := bufio.NewScanner(input.Reader)
	var pkgName, pkgVersion, pkgDependencies string
	pkgs := []*extractor.Inventory{}

	for s.Scan() {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return pkgs, fmt.Errorf("%s halted at %q because of context error: %v", e.Name(), input.Path, err)
		}

		line := s.Text()
		line = strings.TrimSpace(line)

		if len(line) == 0 {
			continue
		}

		if strings.HasPrefix(line, "%NAME%") {
			pkgName, err = extractValue(s)
		} else if strings.HasPrefix(line, "%VERSION%") {
			pkgVersion, err = extractValue(s)
		} else if strings.HasPrefix(line, "%DEPENDS%") {
			pkgDependencies, err = extractValues(s)
		}

		if err != nil {
			if err == io.EOF {
				log.Warnf("Reached EOF for desc file in %v", input.Path)
				break
			}
			return pkgs, fmt.Errorf("%s halted at %q because of context error: %v", e.Name(), input.Path, err)
		}
	}

	if pkgName != "" && pkgVersion != "" {
		i := &extractor.Inventory{
			Name:    pkgName,
			Version: pkgVersion,
			Metadata: &Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				OSID:           m["ID"],
				OSVersionID:    m["VERSION_ID"],
			},
			Locations: []string{input.Path},
		}

		if len(pkgDependencies) != 0 {

			i.Metadata.(*Metadata).PackageDependencies = pkgDependencies
		}

		pkgs = append(pkgs, i)
	}

	return pkgs, nil
}

func extractValue(scanner *bufio.Scanner) (string, error) {
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}

		// EOF
		return "", io.EOF
	}

	return strings.TrimSpace(scanner.Text()), nil
}

func extractValues(scanner *bufio.Scanner) (string, error) {
	var values []string

	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}

			// EOF
			return strings.Join(values, ", "), io.EOF
		}

		line := strings.TrimSpace(scanner.Text())

		if len(line) == 0 {
			break
		}

		values = append(values, line)
	}

	return strings.Join(values, ", "), nil
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
	log.Errorf("os-id not set, fallback to 'linux'")
	return "linux"
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	m := i.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)
	if distro != "" {
		q[purl.Distro] = distro
	}
	if m.PackageDependencies != "" {
		q[purl.PackageDependencies] = m.PackageDependencies
	}

	return &purl.PackageURL{
		Type:       purl.TypePacman,
		Name:       m.PackageName,
		Namespace:  toNamespace(m),
		Version:    i.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}
}

func toDistro(m *Metadata) string {
	// fallback: e.g. 22.04
	if m.OSVersionID != "" {
		return m.OSVersionID
	}
	log.Errorf("VERSION_ID not set in os-release")
	return ""
}
