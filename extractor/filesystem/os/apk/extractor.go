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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/log"
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

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	m, err := osrelease.GetOSRelease(input.ScanRoot)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	rd := textproto.NewReader(bufio.NewReader(input.Reader))
	pkgs := []*extractor.Inventory{}
	for eof := false; !eof; {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return pkgs, fmt.Errorf("%s halted at %q because of context error: %v", e.Name(), input.Path, err)
		}

		h, err := rd.ReadMIMEHeader()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// We might still have one more line of data
				// so return only after it's been parsed.
				eof = true
			} else {
				log.Errorf("Failed to extract all APK packages: %v", err)
				return pkgs, nil
			}
		}
		pkgName := h.Get("P")
		version := h.Get("V")
		if pkgName == "" || version == "" {
			if !eof { // Expected when reaching the last line.
				log.Warnf("APK package name or version is empty (name: %q, version: %q)", pkgName, version)
			}
			continue
		}
		originName := h.Get("o")
		maintainer := h.Get("m")
		arch := h.Get("A")
		license := h.Get("L")
		pkgs = append(pkgs, &extractor.Inventory{
			Name:    pkgName,
			Version: version,
			Metadata: &Metadata{
				PackageName:  pkgName,
				OriginName:   originName,
				OSID:         m["ID"],
				OSVersionID:  m["VERSION_ID"],
				Maintainer:   maintainer,
				Architecture: arch,
				License:      license,
			},
			Locations: []string{input.Path},
		})
	}
	return pkgs, nil
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
