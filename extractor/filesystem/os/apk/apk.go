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

// Package apk extracts packages from the APK database.
package apk

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/apk"
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
		MaxFileSizeBytes: 0,
		Stats:            nil,
	}
}

// Extractor extracts packages from the APK database.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns an APK extractor.
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

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches apk status file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	// Should match the status file.
	if filepath.ToSlash(api.Path()) != "lib/apk/db/installed" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(api.Path(), fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(api.Path(), fileinfo.Size(), stats.FileRequiredResultOK)
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

// Extract extracts packages from lib/apk/db/installed passed through the scan input.
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

// parseSingleApkRecord reads from the scanner a single record,
// returns nil, nil when scanner ends.
func parseSingleApkRecord(scanner *bufio.Scanner) (map[string]string, error) {
	// There is currently 26 keys defined here (Under "Installed Database V2"):
	// https://wiki.alpinelinux.org/wiki/Apk_spec
	group := map[string]string{}

	for scanner.Scan() {
		line := scanner.Text()

		if line != "" {
			key, val, found := strings.Cut(line, ":")

			if !found {
				return nil, fmt.Errorf("invalid line: %q", line)
			}

			group[key] = val
			continue
		}

		// check both that line is empty and we have filled out data in group
		// this avoids double empty lines returning early
		if line == "" && len(group) > 0 {
			// scanner.Err() could only be non nil when Scan() returns false
			// so we can return nil directly here
			return group, nil
		}
	}

	return group, scanner.Err()
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	scanner := bufio.NewScanner(input.Reader)
	packages := []*extractor.Package{}

	for eof := false; !eof; {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s halted at %q because of context error: %w", e.Name(), input.Path, err)
		}

		record, err := parseSingleApkRecord(scanner)
		if err != nil {
			return nil, fmt.Errorf("error while parsing apk status file %q: %w", input.Path, err)
		}

		if len(record) == 0 {
			break
		}

		var sourceCode *extractor.SourceCodeIdentifier
		if commit, ok := record["c"]; ok {
			sourceCode = &extractor.SourceCodeIdentifier{
				Commit: commit,
			}
		}

		var pkg = &extractor.Package{
			Name:    record["P"],
			Version: record["V"],
			Metadata: &Metadata{
				OSID:         m["ID"],
				OSVersionID:  m["VERSION_ID"],
				PackageName:  record["P"],
				OriginName:   record["o"],
				Architecture: record["A"],
				License:      record["L"],
				Maintainer:   record["m"],
			},
			SourceCode: sourceCode,
			Locations:  []string{input.Path},
		}

		if pkg.Name == "" || pkg.Version == "" {
			log.Warnf("APK package name or version is empty (name: %q, version: %q)", pkg.Name, pkg.Version)
			continue
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}

func toNamespace(m *Metadata) string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'alpine'")
	return "alpine"
}

func toDistro(m *Metadata) string {
	// e.g. 3.18.0
	if m.OSVersionID != "" {
		return m.OSVersionID
	}
	log.Errorf("VERSION_ID not set in os-release")
	return ""
}

// ToPURL converts a package created by this extractor into a PURL.
func (e Extractor) ToPURL(p *extractor.Package) *purl.PackageURL {
	m := p.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)
	if distro != "" {
		q[purl.Distro] = distro
	}
	if m.OriginName != "" {
		q[purl.Origin] = m.OriginName
	}
	if m.Architecture != "" {
		q[purl.Arch] = m.Architecture
	}
	return &purl.PackageURL{
		Type:       purl.TypeApk,
		Name:       strings.ToLower(p.Name),
		Namespace:  toNamespace(m),
		Version:    p.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(p *extractor.Package) string {
	version := toDistro(p.Metadata.(*Metadata))
	if version == "" {
		return "Alpine"
	}
	return "Alpine:" + trimDistroVersion(version)
}

// The Alpine OS info might include minor versions such as 3.12.1 while advisories are
// only published against the minor and major versions, i.e. v3.12. Therefore we trim
// any minor versions before putting the value into the Ecosystem.
func trimDistroVersion(distro string) string {
	parts := strings.Split(distro, ".")
	if len(parts) < 2 {
		return "v" + distro
	}
	return fmt.Sprintf("v%s.%s", parts[0], parts[1])
}
