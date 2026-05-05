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

// Package freebsd extracts packages from FreeBSD pkg databases and manifests.
package freebsd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	freebsdmeta "github.com/google/osv-scalibr/extractor/filesystem/os/freebsd/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"

	// sqlite driver needed for parsing local.sqlite files.
	_ "modernc.org/sqlite"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/freebsd"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

// manifestJSON represents the structure of a +MANIFEST file.
type manifestJSON struct {
	Name    string `json:"name"`
	Origin  string `json:"origin"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// Extractor extracts FreeBSD pkg packages from local.sqlite and +MANIFEST files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a FreeBSD pkg extractor.
//
// For most use cases, initialize with:
//
//	e := New(&cpb.PluginConfig{})
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.FreeBSDConfig { return c.GetFreebsd() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches FreeBSD pkg file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())

	if path == "var/db/pkg/local.sqlite" {
		return e.checkFileSize(api, path)
	}

	if strings.HasPrefix(path, "var/db/pkg/") && filepath.Base(path) == "+MANIFEST" {
		return e.checkFileSize(api, path)
	}

	return false
}

func (e Extractor) checkFileSize(api filesystem.FileAPI, path string) bool {
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

// Extract extracts packages from FreeBSD pkg files passed through the scan input.
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
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("freebsd.extract: %w", err)
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.GetOSRelease(): %v", err)
	}

	path := filepath.ToSlash(input.Path)
	if path == "var/db/pkg/local.sqlite" {
		return e.extractFromSQLite(ctx, input, m)
	}

	return e.extractFromManifest(ctx, input, m)
}

func (e Extractor) extractFromSQLite(ctx context.Context, input *filesystem.ScanInput, osrelease map[string]string) ([]*extractor.Package, error) {
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

	db, err := sql.Open("sqlite", absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open FreeBSD pkg database %s: %w", absPath, err)
	}
	defer db.Close()

	if err := e.validateSQLiteSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("invalid FreeBSD pkg database %s: %w", absPath, err)
	}

	return e.queryPackages(ctx, db, osrelease, input.Path)
}

func (e Extractor) validateSQLiteSchema(ctx context.Context, db *sql.DB) error {
	var tableName string
	err := db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name='packages'").Scan(&tableName)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("database does not contain packages table")
		}
		return fmt.Errorf("failed to query database schema: %w", err)
	}
	return nil
}

func (e Extractor) queryPackages(ctx context.Context, db *sql.DB, osrelease map[string]string, path string) ([]*extractor.Package, error) {
	rows, err := db.QueryContext(ctx, "SELECT origin, name, version, arch FROM packages")
	if err != nil {
		return nil, fmt.Errorf("failed to query packages: %w", err)
	}
	defer rows.Close()

	var pkgs []*extractor.Package
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return pkgs, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		var origin, name, version, arch string
		if err := rows.Scan(&origin, &name, &version, &arch); err != nil {
			return nil, fmt.Errorf("failed to scan package row: %w", err)
		}

		m := &freebsdmeta.Metadata{
			PackageName:    name,
			PackageVersion: version,
			Origin:         origin,
			Arch:           arch,
			OSID:           osrelease["ID"],
			OSVersionID:    osrelease["VERSION_ID"],
		}

		p := &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeFreeBSD,
			Metadata: m,
			Location: extractor.LocationFromPath(path),
		}
		pkgs = append(pkgs, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating package rows: %w", err)
	}

	return pkgs, nil
}

func (e Extractor) extractFromManifest(ctx context.Context, input *filesystem.ScanInput, osrelease map[string]string) ([]*extractor.Package, error) {
	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest manifestJSON
	if err := json.Unmarshal(b, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	if manifest.Name == "" || manifest.Version == "" {
		return nil, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
	}

	m := &freebsdmeta.Metadata{
		PackageName:    manifest.Name,
		PackageVersion: manifest.Version,
		Origin:         manifest.Origin,
		Arch:           manifest.Arch,
		OSID:           osrelease["ID"],
		OSVersionID:    osrelease["VERSION_ID"],
	}

	p := &extractor.Package{
		Name:     manifest.Name,
		Version:  manifest.Version,
		PURLType: purl.TypeFreeBSD,
		Metadata: m,
		Location: extractor.LocationFromPath(input.Path),
	}

	return []*extractor.Package{p}, nil
}
