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

//go:build !windows

// Package rpm extracts packages from rpm database.
package rpm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	rpmdb "github.com/erikvarga/go-rpmdb/pkg"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	// SQLite driver needed for parsing rpmdb.sqlite files.
	_ "modernc.org/sqlite"
)

// Name is the name for the RPM extractor
const Name = "os/rpm"

const defaultTimeout = 5 * time.Minute

var (
	requiredDirectory = []string{
		"usr/lib/sysimage/rpm/",
		"var/lib/rpm/",
		"usr/share/rpm/",
	}

	requiredFilename = []string{
		// Berkley DB (old format)
		"Packages",
		// NDB (very rare alternative to sqlite)
		"Packages.db",
		// SQLite3 (new format)
		"rpmdb.sqlite",
	}
)

// Config contains RPM specific configuration values
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
	// Timeout is the timeout duration for parsing the RPM database.
	Timeout time.Duration
}

// DefaultConfig returns the default configuration values for the RPM extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: 0,
		Timeout:          defaultTimeout,
	}
}

// Extractor extracts rpm packages from rpm database.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
	Timeout          time.Duration
}

// New returns an RPM extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
		Timeout:          cfg.Timeout,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches rpm status file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	dir, filename := filepath.Split(filepath.ToSlash(path))
	if !slices.Contains(requiredDirectory, dir) || !slices.Contains(requiredFilename, filename) {
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

// Extract extracts packages from rpm status files passed through the scan input.
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
	absPath, err := input.GetRealPath()
	if err != nil {
		return nil, fmt.Errorf("GetRealPath(%v): %w", input, err)
	}
	if input.Root == "" {
		// The file got copied to a temporary dir, remove it at the end.
		defer func() {
			dir := filepath.Dir(absPath)
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("os.RemoveAll(%q): %v", dir, err)
			}
		}()
	}
	rpmPkgs, err := e.parseRPMDB(ctx, absPath)
	if err != nil {
		return nil, fmt.Errorf("ParseRPMDB(%s): %w", absPath, err)
	}

	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	pkgs := []*extractor.Package{}
	for _, p := range rpmPkgs {
		metadata := &rpmmeta.Metadata{
			PackageName:  p.Name,
			SourceRPM:    p.SourceRPM,
			Epoch:        p.Epoch,
			OSName:       m["NAME"],
			OSPrettyName: m["PRETTY_NAME"],
			OSID:         m["ID"],
			OSVersionID:  m["VERSION_ID"],
			OSBuildID:    m["BUILD_ID"],
			Vendor:       p.Vendor,
			Architecture: p.Architecture,
		}

		pkgs = append(pkgs, &extractor.Package{
			Name:      p.Name,
			Version:   fmt.Sprintf("%s-%s", p.Version, p.Release),
			PURLType:  purl.TypeRPM,
			Locations: []string{input.Path},
			Metadata:  metadata,
			Licenses:  []string{p.License},
		})
	}

	return pkgs, nil
}

// parseRPMDB returns a slice of OS packages parsed from a RPM DB.
func (e Extractor) parseRPMDB(ctx context.Context, path string) ([]rpmPackageInfo, error) {
	db, err := rpmdb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var pkgs []*rpmdb.PackageInfo
	if e.Timeout == 0 {
		pkgs, err = db.ListPackages()
		if err != nil {
			return nil, err
		}
	} else {
		ctx, cancelFunc := context.WithTimeout(ctx, e.Timeout)
		defer cancelFunc()

		// The timeout is only for corrupt bdb databases
		pkgs, err = db.ListPackagesWithContext(ctx)
		if err != nil {
			return nil, err
		}
	}

	var result []rpmPackageInfo
	for _, pkg := range pkgs {
		newPkg := rpmPackageInfo{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Release:      pkg.Release,
			Epoch:        pkg.EpochNum(),
			SourceRPM:    pkg.SourceRpm,
			Vendor:       pkg.Vendor,
			Architecture: pkg.Arch,
			License:      pkg.License,
		}

		result = append(result, newPkg)
	}

	return result, nil
}

type rpmPackageInfo struct {
	Name         string
	Version      string
	Release      string
	Epoch        int
	SourceRPM    string
	Maintainer   string
	Vendor       string
	Architecture string
	License      string
}
