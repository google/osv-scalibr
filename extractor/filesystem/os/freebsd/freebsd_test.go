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

package freebsd_test

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/freebsd"
	freebsdmeta "github.com/google/osv-scalibr/extractor/filesystem/os/freebsd/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
	_ "modernc.org/sqlite"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "local.sqlite required",
			path:             "var/db/pkg/local.sqlite",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "+MANIFEST required",
			path:             "var/db/pkg/curl-8.4.0/+MANIFEST",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "wrong path not required",
			path:         "var/db/pkg/other.db",
			wantRequired: false,
		},
		{
			name:         "+MANIFEST outside pkg dir not required",
			path:         "var/db/+MANIFEST",
			wantRequired: false,
		},
		{
			name:             "file size limit exceeded",
			path:             "var/db/pkg/local.sqlite",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "file under limit required",
			path:             "var/db/pkg/local.sqlite",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := freebsd.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("freebsd.New: %v", err)
			}
			e.(*freebsd.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T) (root string, path string)
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "valid manifest json",
			setup: func(t *testing.T) (string, string) {
				return "testdata", "manifest.json"
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "curl",
					Version:  "8.4.0",
					PURLType: purl.TypeFreeBSD,
					Metadata: &freebsdmeta.Metadata{
						PackageName:    "curl",
						PackageVersion: "8.4.0",
						Origin:         "ftp/curl",
						Arch:           "freebsd:14:x86:64",
					},
					Location: extractor.LocationFromPath("manifest.json"),
				},
			},
		},
		{
			name: "valid sqlite database",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				dbDir := filepath.Join(tmpDir, "var", "db", "pkg")
				if err := os.MkdirAll(dbDir, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				dbPath := filepath.Join(dbDir, "local.sqlite")
				if err := createTestDatabase(dbPath); err != nil {
					t.Fatalf("createTestDatabase: %v", err)
				}
				return tmpDir, "var/db/pkg/local.sqlite"
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "curl",
					Version:  "8.4.0",
					PURLType: purl.TypeFreeBSD,
					Metadata: &freebsdmeta.Metadata{
						PackageName:    "curl",
						PackageVersion: "8.4.0",
						Origin:         "ftp/curl",
						Arch:           "freebsd:14:x86:64",
					},
					Location: extractor.LocationFromPath("var/db/pkg/local.sqlite"),
				},
				{
					Name:     "openssl",
					Version:  "3.0.12",
					PURLType: purl.TypeFreeBSD,
					Metadata: &freebsdmeta.Metadata{
						PackageName:    "openssl",
						PackageVersion: "3.0.12",
						Origin:         "security/openssl",
						Arch:           "freebsd:14:x86:64",
					},
					Location: extractor.LocationFromPath("var/db/pkg/local.sqlite"),
				},
			},
		},
		{
			name: "invalid sqlite database",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				dbDir := filepath.Join(tmpDir, "var", "db", "pkg")
				if err := os.MkdirAll(dbDir, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				dbPath := filepath.Join(dbDir, "local.sqlite")
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatalf("sql.Open: %v", err)
				}
				defer db.Close()
				ctx := context.Background()
				_, err = db.ExecContext(ctx, "CREATE TABLE other (id INTEGER)")
				if err != nil {
					t.Fatalf("db.ExecContext: %v", err)
				}
				return tmpDir, "var/db/pkg/local.sqlite"
			},
			wantErr: extracttest.ContainsErrStr{Str: "invalid FreeBSD pkg database"},
		},
		{
			name: "invalid json returns error",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				manifestPath := filepath.Join(tmpDir, "+MANIFEST")
				if err := os.WriteFile(manifestPath, []byte("not json"), 0o644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return tmpDir, "+MANIFEST"
			},
			wantErr: extracttest.ContainsErrStr{Str: "failed to parse manifest JSON"},
		},
		{
			name: "empty manifest returns no packages",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				manifestPath := filepath.Join(tmpDir, "+MANIFEST")
				if err := os.WriteFile(manifestPath, []byte("{}"), 0o644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return tmpDir, "+MANIFEST"
			},
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, path := tt.setup(t)

			extr := freebsd.Extractor{}
			scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path:         path,
				FakeScanRoot: root,
			})
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), path, diff)
			}
		})
	}
}

func createTestDatabase(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	schema := `
	CREATE TABLE packages (
		origin TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		version TEXT NOT NULL,
		desc TEXT NOT NULL,
		arch TEXT NOT NULL,
		maintainer TEXT NOT NULL,
		prefix TEXT NOT NULL,
		flatsize INTEGER NOT NULL,
		automatic INTEGER NOT NULL,
		licenselogic INTEGER NOT NULL
	);
	`
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return err
	}

	packages := []struct {
		origin  string
		name    string
		version string
		desc    string
		arch    string
	}{
		{"ftp/curl", "curl", "8.4.0", "Command line tool for transferring data", "freebsd:14:x86:64"},
		{"security/openssl", "openssl", "3.0.12", "SSL/TLS toolkit", "freebsd:14:x86:64"},
	}

	for _, pkg := range packages {
		_, err := db.ExecContext(ctx,
			"INSERT INTO packages (origin, name, version, desc, arch, maintainer, prefix, flatsize, automatic, licenselogic) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			pkg.origin, pkg.name, pkg.version, pkg.desc, pkg.arch, "test@example.com", "/usr/local", 1000, 0, 1)
		if err != nil {
			return err
		}
	}

	return nil
}
