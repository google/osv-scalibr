// Copyright 2026 Google LLC
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

// Package photon extracts packages from Photon OS (VMware Photon) RPM databases.
// Photon OS is a lightweight Linux container OS maintained by VMware/Broadcom,
// widely used as the base for VMware vSphere, Tanzu, and Harbor Container Registry.
// Its packages are tracked under the "Photon OS" ecosystem in OSV.dev.
package photon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"

	// SQLite driver needed for parsing rpmdb.sqlite files.
	_ "modernc.org/sqlite"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/photon"

	defaultTimeout = 5 * time.Minute

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)

	// photonOSID is the ID value in /etc/os-release for Photon OS.
	photonOSID = "photon"
)

var (
	// requiredDirectory lists paths where the RPM database may reside on Photon OS.
	requiredDirectory = []string{
		"usr/lib/sysimage/rpm/",
		"var/lib/rpm/",
		"usr/share/rpm/",
	}

	// requiredFilename lists the RPM database filenames.
	requiredFilename = []string{
		// Berkley DB (old format)
		"Packages",
		// NDB (very rare alternative to sqlite)
		"Packages.db",
		// SQLite3 (new format, used by Photon OS 4.0+)
		"rpmdb.sqlite",
	}
)

// Extractor extracts Photon OS packages from the RPM database.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
	Timeout          time.Duration
}

// New returns a Photon OS extractor.
//
// For most use cases, initialize with:
//
//	e := New(&cpb.PluginConfig{})
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	timeout := defaultTimeout
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes, Timeout: timeout}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is an RPM database file on a Photon OS system.
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
	if e.maxFileSizeBytes > noLimitMaxFileSizeBytes && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from Photon OS RPM database files.
// It first verifies the system is Photon OS by reading /etc/os-release,
// then emits packages with the correct "Photon OS" ecosystem namespace.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(ctx, input)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	// Verify the system is Photon OS before extracting.
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("photon: osrelease.GetOSRelease(): %v", err)
		return nil, nil
	}

	osID := strings.ToLower(m["ID"])
	if osID != photonOSID {
		// Not a Photon OS system; skip.
		return nil, nil
	}

	absPath, err := input.GetRealPath()
	if err != nil {
		return nil, fmt.Errorf("GetRealPath(%v): %w", input, err)
	}
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(absPath)
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("os.RemoveAll(%q): %v", dir, err)
			}
		}()
	}

	rpmPkgs, err := e.parseRPMDB(ctx, absPath)
	if err != nil {
		return nil, fmt.Errorf("parseRPMDB(%s): %w", absPath, err)
	}

	var pkgs []*extractor.Package
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

		// Photon OS packages use purl.TypeRPM with namespace "photon" (from OSID).
		// The namespace is automatically derived from metadata.OSID via
		// rpmmeta.Metadata.ToNamespace(), which maps to the "Photon OS" ecosystem
		// in OSV.dev via the inventory/osvecosystem package.
		pkgs = append(pkgs, &extractor.Package{
			Name:     p.Name,
			Version:  fmt.Sprintf("%s-%s", p.Version, p.Release),
			PURLType: purl.TypeRPM,
			Location: extractor.LocationFromPath(input.Path),
			Metadata: metadata,
			Licenses: []string{p.License},
		})
	}

	return pkgs, nil
}

// parseRPMDB returns a slice of package info parsed from an RPM DB file.
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

		pkgs, err = db.ListPackagesWithContext(ctx)
		if err != nil {
			return nil, err
		}
	}

	var result []rpmPackageInfo
	for _, pkg := range pkgs {
		result = append(result, rpmPackageInfo{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Release:      pkg.Release,
			Epoch:        pkg.EpochNum(),
			SourceRPM:    pkg.SourceRpm,
			Vendor:       pkg.Vendor,
			Architecture: pkg.Arch,
			License:      pkg.License,
		})
	}

	return result, nil
}

type rpmPackageInfo struct {
	Name         string
	Version      string
	Release      string
	Epoch        int
	SourceRPM    string
	Vendor       string
	Architecture string
	License      string
}
