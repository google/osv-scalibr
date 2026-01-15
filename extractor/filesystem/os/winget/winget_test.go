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

package winget

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/winget/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/fakefs"
	_ "modernc.org/sqlite"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "WingetInstalledDB_ReturnsTrue",
			path: "/Users/test/AppData/Local/Packages/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe/LocalState/Microsoft.Winget.Source_8wekyb3d8bbwe/installed.db",
			want: true,
		},
		{
			name: "StoreEdgeFDInstalledDB_ReturnsTrue",
			path: "/Users/test/AppData/Local/Packages/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe/LocalState/StoreEdgeFD/installed.db",
			want: true,
		},
		{
			name: "StateRepositoryMachine_ReturnsTrue",
			path: "/ProgramData/Microsoft/Windows/AppRepository/StateRepository-Machine.srd",
			want: true,
		},
		{
			name: "RandomSQLiteFile_ReturnsFalse",
			path: "/some/random/path/database.db",
			want: false,
		},
		{
			name: "WingetDBWrongPath_ReturnsFalse",
			path: "/wrong/path/installed.db",
			want: false,
		},
	}

	wingetExtractor, err := New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: 1000,
			})
			got := wingetExtractor.FileRequired(api)
			if got != tt.want {
				t.Errorf("FileRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name    string
		setupDB func(string) error
		want    []*extractor.Package
		wantErr bool
	}{
		{
			name: "ValidDatabase_ReturnsPackages",
			setupDB: func(dbPath string) error {
				return createTestDatabase(dbPath, []TestPackage{
					{
						ID:       "Git.Git",
						Name:     "Git",
						Version:  "2.50.1",
						Moniker:  "git",
						Channel:  "",
						Tags:     []string{"git", "vcs"},
						Commands: []string{"git"},
					},
					{
						ID:       "Microsoft.VisualStudioCode",
						Name:     "Microsoft Visual Studio Code",
						Version:  "1.103.1",
						Moniker:  "vscode",
						Channel:  "stable",
						Tags:     []string{"developer-tools", "editor"},
						Commands: []string{"code"},
					},
				})
			},
			want: []*extractor.Package{
				{
					Name:      "Git.Git",
					Version:   "2.50.1",
					PURLType:  purl.TypeWinget,
					Locations: []string{"test.db"},
					Metadata: &metadata.Metadata{
						Name:     "Git",
						ID:       "Git.Git",
						Version:  "2.50.1",
						Moniker:  "git",
						Channel:  "",
						Tags:     []string{"git", "vcs"},
						Commands: []string{"git"},
					},
				},
				{
					Name:      "Microsoft.VisualStudioCode",
					Version:   "1.103.1",
					PURLType:  purl.TypeWinget,
					Locations: []string{"test.db"},
					Metadata: &metadata.Metadata{
						Name:     "Microsoft Visual Studio Code",
						ID:       "Microsoft.VisualStudioCode",
						Version:  "1.103.1",
						Moniker:  "vscode",
						Channel:  "stable",
						Tags:     []string{"developer-tools", "editor"},
						Commands: []string{"code"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "EmptyDatabase_ReturnsEmpty",
			setupDB: func(dbPath string) error {
				return createTestDatabase(dbPath, []TestPackage{})
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "InvalidDatabase_ReturnsError",
			setupDB: func(dbPath string) error {
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					return err
				}
				defer db.Close()
				ctx := context.Background()
				_, err = db.ExecContext(ctx, "CREATE TABLE test (id INTEGER)")
				return err
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dbPath := filepath.Join(tmpDir, "test.db")

			if err := tt.setupDB(dbPath); err != nil {
				t.Fatalf("Failed to setup test database: %v", err)
			}

			wingetExtractor, err := New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}

			// Create a custom Extract method that bypasses GetRealPath for testing
			got, err := func() ([]*extractor.Package, error) {
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					return nil, fmt.Errorf("failed to open Winget database %s: %w", dbPath, err)
				}
				defer db.Close()

				ctx := context.Background()
				ext := wingetExtractor.(*Extractor)
				if err := ext.validateDatabase(ctx, db); err != nil {
					return nil, fmt.Errorf("invalid Winget database %s: %w", dbPath, err)
				}

				packages, err := ext.extractPackages(ctx, db)
				if err != nil {
					return nil, fmt.Errorf("failed to extract packages from %s: %w", dbPath, err)
				}

				var extPackages []*extractor.Package
				for _, pkg := range packages {
					if err := ctx.Err(); err != nil {
						return nil, fmt.Errorf("%s halted due to context error: %w", wingetExtractor.Name(), err)
					}

					extPkg := &extractor.Package{
						Name:      pkg.ID,
						Version:   pkg.Version,
						PURLType:  purl.TypeWinget,
						Locations: []string{"test.db"},
						Metadata: &metadata.Metadata{
							Name:     pkg.Name,
							ID:       pkg.ID,
							Version:  pkg.Version,
							Moniker:  pkg.Moniker,
							Channel:  pkg.Channel,
							Tags:     pkg.Tags,
							Commands: pkg.Commands,
						},
					}
					extPackages = append(extPackages, extPkg)
				}

				return extPackages, nil
			}()
			if (err != nil) != tt.wantErr {
				t.Errorf("Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Extract() packages mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestExtractorInterface(t *testing.T) {
	wingetExtractor, err := New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	if wingetExtractor.Name() != Name {
		t.Errorf("Name() = %v, want %v", wingetExtractor.Name(), Name)
	}

	if wingetExtractor.Version() != 0 {
		t.Errorf("Version() = %v, want %v", wingetExtractor.Version(), 0)
	}

	caps := wingetExtractor.Requirements()
	if caps.OS != 2 { // OSWindows = 2
		t.Errorf("Requirements().OS = %v, want 2 (OSWindows)", caps.OS)
	}

	if caps.RunningSystem {
		t.Error("Requirements().RunningSystem should be false for filesystem extractor")
	}
}

// TestPackage represents a test package for database creation
type TestPackage struct {
	ID       string
	Name     string
	Version  string
	Moniker  string
	Channel  string
	Tags     []string
	Commands []string
}

// createTestDatabase creates a SQLite database with the Winget schema and test data
func createTestDatabase(dbPath string, packages []TestPackage) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()

	// Create schema
	schema := `
	CREATE TABLE [metadata](
		[name] TEXT PRIMARY KEY NOT NULL,
		[value] TEXT NOT NULL);
	CREATE TABLE [ids](rowid INTEGER PRIMARY KEY, [id] TEXT NOT NULL);
	CREATE UNIQUE INDEX [ids_pkindex] ON [ids]([id]);
	CREATE TABLE [names](rowid INTEGER PRIMARY KEY, [name] TEXT NOT NULL);
	CREATE UNIQUE INDEX [names_pkindex] ON [names]([name]);
	CREATE TABLE [monikers](rowid INTEGER PRIMARY KEY, [moniker] TEXT NOT NULL);
	CREATE UNIQUE INDEX [monikers_pkindex] ON [monikers]([moniker]);
	CREATE TABLE [versions](rowid INTEGER PRIMARY KEY, [version] TEXT NOT NULL);
	CREATE UNIQUE INDEX [versions_pkindex] ON [versions]([version]);
	CREATE TABLE [channels](rowid INTEGER PRIMARY KEY, [channel] TEXT NOT NULL);
	CREATE UNIQUE INDEX [channels_pkindex] ON [channels]([channel]);
	CREATE TABLE [manifest](rowid INTEGER PRIMARY KEY, [id] INT64 NOT NULL, [name] INT64 NOT NULL, [moniker] INT64 NOT NULL, [version] INT64 NOT NULL, [channel] INT64 NOT NULL, [pathpart] INT64 NOT NULL, hash BLOB, arp_min_version INT64, arp_max_version INT64);
	CREATE TABLE [tags](rowid INTEGER PRIMARY KEY, [tag] TEXT NOT NULL);
	CREATE UNIQUE INDEX [tags_pkindex] ON [tags]([tag]);
	CREATE TABLE [tags_map]([manifest] INT64 NOT NULL, [tag] INT64 NOT NULL, PRIMARY KEY([tag], [manifest])) WITHOUT ROWID;
	CREATE TABLE [commands](rowid INTEGER PRIMARY KEY, [command] TEXT NOT NULL);
	CREATE UNIQUE INDEX [commands_pkindex] ON [commands]([command]);
	CREATE TABLE [commands_map]([manifest] INT64 NOT NULL, [command] INT64 NOT NULL, PRIMARY KEY([command], [manifest])) WITHOUT ROWID;
	`

	_, err = db.ExecContext(ctx, schema)
	if err != nil {
		return err
	}

	// Insert test data
	for i, pkg := range packages {
		manifestID := i + 1

		// Insert lookup table values
		_, err = db.ExecContext(ctx, "INSERT INTO ids (rowid, id) VALUES (?, ?)", manifestID, pkg.ID)
		if err != nil {
			return err
		}

		_, err = db.ExecContext(ctx, "INSERT INTO names (rowid, name) VALUES (?, ?)", manifestID, pkg.Name)
		if err != nil {
			return err
		}

		_, err = db.ExecContext(ctx, "INSERT INTO monikers (rowid, moniker) VALUES (?, ?)", manifestID, pkg.Moniker)
		if err != nil {
			return err
		}

		_, err = db.ExecContext(ctx, "INSERT INTO versions (rowid, version) VALUES (?, ?)", manifestID, pkg.Version)
		if err != nil {
			return err
		}

		_, err = db.ExecContext(ctx, "INSERT INTO channels (rowid, channel) VALUES (?, ?)", manifestID, pkg.Channel)
		if err != nil {
			return err
		}

		// Insert manifest
		_, err = db.ExecContext(ctx, "INSERT INTO manifest (rowid, id, name, moniker, version, channel, pathpart) VALUES (?, ?, ?, ?, ?, ?, ?)",
			manifestID, manifestID, manifestID, manifestID, manifestID, manifestID, -1)
		if err != nil {
			return err
		}

		// Insert tags
		for j, tag := range pkg.Tags {
			tagID := i*100 + j + 1
			_, err = db.ExecContext(ctx, "INSERT INTO tags (rowid, tag) VALUES (?, ?)", tagID, tag)
			if err != nil {
				return err
			}
			_, err = db.ExecContext(ctx, "INSERT INTO tags_map (manifest, tag) VALUES (?, ?)", manifestID, tagID)
			if err != nil {
				return err
			}
		}

		// Insert commands
		for j, command := range pkg.Commands {
			commandID := i*100 + j + 1
			_, err = db.ExecContext(ctx, "INSERT INTO commands (rowid, command) VALUES (?, ?)", commandID, command)
			if err != nil {
				return err
			}
			_, err = db.ExecContext(ctx, "INSERT INTO commands_map (manifest, command) VALUES (?, ?)", manifestID, commandID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
