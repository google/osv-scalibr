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

// Package flatpak extracts packages from flatpak metainfo files.
package flatpak

import (
	"context"
	"encoding/xml"
	"fmt"
	"io/fs"
	"regexp"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/flatpak"

	// defaultMaxFileSizeBytes is set to 0 since the xml file is per package and is usually small.
	defaultMaxFileSizeBytes = 0
)

// Metainfo is used to read the flatpak metainfo xml file.
type Metainfo struct {
	ID        string   `xml:"id"`
	Name      []string `xml:"name"`
	Developer string   `xml:"developer_name"`
	Releases  struct {
		Release []struct {
			Version     string `xml:"version,attr"`
			ReleaseDate string `xml:"date,attr"`
		} `xml:"release"`
	} `xml:"releases"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the Flatpak extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts Flatpak packages from *.metainfo.xml files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Flatpak extractor.
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

// Should be metainfo.xml inside flatpak metainfo dir either globally or for a specific user.
var filePathRegex = regexp.MustCompile(`flatpak/app/.*/export/share/metainfo/.*metainfo.xml$`)

// FileRequired returns true if the specified file matches the metainfo xml file pattern.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	if match := filePathRegex.FindString(path); match == "" {
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

// Extract extracts packages from metainfo xml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	i, err := e.extractFromInput(input)
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
	if err != nil {
		return nil, fmt.Errorf("flatpak.extract(%s): %w", input.Path, err)
	}
	if i == nil {
		return []*extractor.Inventory{}, nil
	}
	return []*extractor.Inventory{i}, nil
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) (*extractor.Inventory, error) {
	m, err := osrelease.GetOSRelease(input.ScanRoot)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	var f Metainfo
	err = xml.NewDecoder(input.Reader).Decode(&f)
	if err != nil {
		return nil, fmt.Errorf("failed to xml decode: %v", err)
	}

	pkgName := ""
	if len(f.Name) > 0 {
		pkgName = f.Name[0]
	}

	pkgVersion := ""
	if len(f.Releases.Release) > 0 {
		pkgVersion = f.Releases.Release[0].Version // We only want the latest version.
	}
	if pkgVersion == "" {
		return nil, fmt.Errorf("PackageVersion: %v does not exist", pkgVersion)
	}

	i := &extractor.Inventory{
		Name:    f.ID,
		Version: pkgVersion,
		Metadata: &Metadata{
			PackageName:    pkgName,
			PackageID:      f.ID,
			PackageVersion: pkgVersion,
			ReleaseDate:    f.Releases.Release[0].ReleaseDate,
			OSName:         m["NAME"],
			OSID:           m["ID"],
			OSVersionID:    m["VERSION_ID"],
			OSBuildID:      m["BUILD_ID"],
			Developer:      f.Developer,
		},
		Locations: []string{input.Path},
	}

	return i, nil
}

func toNamespace(m *Metadata) string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to ''")
	return ""
}

func toDistro(m *Metadata) string {
	v := m.OSVersionID
	if v == "" {
		v = m.OSBuildID
		if v == "" {
			log.Errorf("VERSION_ID and BUILD_ID not set in os-release")
			return ""
		}
		log.Errorf("os-release[VERSION_ID] not set, fallback to BUILD_ID")
	}

	id := m.OSID
	if id == "" {
		log.Errorf("os-release[ID] not set, fallback to ''")
		return v
	}
	return fmt.Sprintf("%s-%s", id, v)
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	m := i.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)
	if distro != "" {
		q[purl.Distro] = distro
	}
	return &purl.PackageURL{
		Type:       purl.TypeFlatpak,
		Namespace:  toNamespace(m),
		Name:       i.Name,
		Version:    i.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
