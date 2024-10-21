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

// Package apk extracts packages from the APK database.
package apk

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
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

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches apk status file pattern.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	// Should match the status file.
	if filepath.ToSlash(path) != "lib/apk/db/installed" {
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

// Extract extracts packages from lib/apk/db/installed passed through the scan input.
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

func groupApkPackageLines(scanner *bufio.Scanner) ([][]string, error) {
	var groups [][]string
	var group []string

	for scanner.Scan() {
		line := scanner.Text()

		if line != "" {
			group = append(group, line)
			continue
		}
		if len(group) > 0 {
			groups = append(groups, group)
		}
		group = make([]string, 0)
	}

	if len(group) > 0 {
		groups = append(groups, group)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while scanning: %w", err)
	}

	return groups, nil
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	scanner := bufio.NewScanner(input.Reader)
	packageGroups, err := groupApkPackageLines(scanner)
	inventories := make([]*extractor.Inventory, 0, len(packageGroups))

	if err != nil {
		return nil, fmt.Errorf("error while parsing apk status file: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s halted at %q because of context error: %v", e.Name(), input.Path, err)
	}

	for _, group := range packageGroups {
		var metadata = &Metadata{
			OSID:        m["ID"],
			OSVersionID: m["VERSION_ID"],
		}
		var pkg = &extractor.Inventory{
			Metadata:  metadata,
			Locations: []string{input.Path},
		}

		// File SPECS: https://wiki.alpinelinux.org/wiki/Apk_spec
		for _, line := range group {
			switch {
			case strings.HasPrefix(line, "P:"):
				pkg.Name = strings.TrimPrefix(line, "P:")
				metadata.PackageName = pkg.Name
			case strings.HasPrefix(line, "V:"):
				pkg.Version = strings.TrimPrefix(line, "V:")
			case strings.HasPrefix(line, "c:"):
				pkg.SourceCode = &extractor.SourceCodeIdentifier{
					Commit: strings.TrimPrefix(line, "c:"),
				}
			case strings.HasPrefix(line, "o:"):
				metadata.OriginName = strings.TrimPrefix(line, "o:")
			case strings.HasPrefix(line, "A:"):
				metadata.Architecture = strings.TrimPrefix(line, "A:")
			case strings.HasPrefix(line, "L:"):
				metadata.License = strings.TrimPrefix(line, "L:")
			case strings.HasPrefix(line, "m:"):
				metadata.Maintainer = strings.TrimPrefix(line, "m:")
			}
		}

		if pkg.Name == "" || pkg.Version == "" {
			log.Warnf("APK package name or version is empty (name: %q, version: %q)", pkg.Name, pkg.Version)
			continue
		}

		inventories = append(inventories, pkg)
	}

	return inventories, nil
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

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	m := i.Metadata.(*Metadata)
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
		Name:       strings.ToLower(i.Name),
		Namespace:  toNamespace(m),
		Version:    i.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) string {
	version := toDistro(i.Metadata.(*Metadata))
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
