//go:build windows

package winget

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"github.com/google/osv-scalibr/inventory"
	_ "modernc.org/sqlite"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name    string
		setupDB func(string) error
		config  Configuration
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
						Channel:  "",
						Tags:     []string{"developer-tools", "editor"},
						Commands: []string{"code"},
					},
				})
			},
			want: []*extractor.Package{
				{
					Name:     "Git.Git",
					Version:  "2.50.1",
					PURLType: "winget",
					Metadata: &metadata.WingetPackage{
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
					Name:     "Microsoft.VisualStudioCode",
					Version:  "1.103.1",
					PURLType: "winget",
					Metadata: &metadata.WingetPackage{
						Name:     "Microsoft Visual Studio Code",
						ID:       "Microsoft.VisualStudioCode",
						Version:  "1.103.1",
						Moniker:  "vscode",
						Channel:  "",
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
			want:    []*extractor.Package{},
			wantErr: false,
		},
		{
			name: "InvalidDatabase_ReturnsError",
			setupDB: func(dbPath string) error {
				// Create a database without the manifest table
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					return err
				}
				defer db.Close()
				_, err = db.Exec("CREATE TABLE test (id INTEGER)")
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

			config := Configuration{
				DatabasePaths: []string{dbPath},
			}
			if len(tt.config.DatabasePaths) > 0 {
				config = tt.config
			}

			extractor := New(config)
			input := &standalone.ScanInput{}

			got, err := extractor.Extract(context.Background(), input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, got.Packages); diff != "" {
					t.Errorf("Extract() packages mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestExtract_NoValidDatabase(t *testing.T) {
	config := Configuration{
		DatabasePaths: []string{
			"/nonexistent/path1.db",
			"/nonexistent/path2.db",
		},
	}

	extractor := New(config)
	input := &standalone.ScanInput{}

	_, err := extractor.Extract(context.Background(), input)
	if err == nil {
		t.Error("Expected error when no valid database found")
	}
}

func TestExtractorInterface(t *testing.T) {
	extractor := NewDefault()

	if extractor.Name() != Name {
		t.Errorf("Name() = %v, want %v", extractor.Name(), Name)
	}

	if extractor.Version() != 0 {
		t.Errorf("Version() = %v, want %v", extractor.Version(), 0)
	}

	caps := extractor.Requirements()
	if caps.OS.String() != "windows" {
		t.Errorf("Requirements().OS = %v, want windows", caps.OS)
	}

	if !caps.RunningSystem {
		t.Error("Requirements().RunningSystem should be true")
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

	_, err = db.Exec(schema)
	if err != nil {
		return err
	}

	// Insert test data
	for i, pkg := range packages {
		manifestID := i + 1

		// Insert lookup table values
		_, err = db.Exec("INSERT INTO ids (rowid, id) VALUES (?, ?)", manifestID, pkg.ID)
		if err != nil {
			return err
		}

		_, err = db.Exec("INSERT INTO names (rowid, name) VALUES (?, ?)", manifestID, pkg.Name)
		if err != nil {
			return err
		}

		_, err = db.Exec("INSERT INTO monikers (rowid, moniker) VALUES (?, ?)", manifestID, pkg.Moniker)
		if err != nil {
			return err
		}

		_, err = db.Exec("INSERT INTO versions (rowid, version) VALUES (?, ?)", manifestID, pkg.Version)
		if err != nil {
			return err
		}

		_, err = db.Exec("INSERT INTO channels (rowid, channel) VALUES (?, ?)", manifestID, pkg.Channel)
		if err != nil {
			return err
		}

		// Insert manifest
		_, err = db.Exec("INSERT INTO manifest (rowid, id, name, moniker, version, channel, pathpart) VALUES (?, ?, ?, ?, ?, ?, ?)",
			manifestID, manifestID, manifestID, manifestID, manifestID, manifestID, -1)
		if err != nil {
			return err
		}

		// Insert tags
		for j, tag := range pkg.Tags {
			tagID := i*100 + j + 1
			_, err = db.Exec("INSERT INTO tags (rowid, tag) VALUES (?, ?)", tagID, tag)
			if err != nil {
				return err
			}
			_, err = db.Exec("INSERT INTO tags_map (manifest, tag) VALUES (?, ?)", manifestID, tagID)
			if err != nil {
				return err
			}
		}

		// Insert commands
		for j, command := range pkg.Commands {
			commandID := i*100 + j + 1
			_, err = db.Exec("INSERT INTO commands (rowid, command) VALUES (?, ?)", commandID, command)
			if err != nil {
				return err
			}
			_, err = db.Exec("INSERT INTO commands_map (manifest, command) VALUES (?, ?)", manifestID, commandID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
