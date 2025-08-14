//go:build windows

// Package winget extracts installed packages from Windows Package Manager (Winget) database.
package winget

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	_ "modernc.org/sqlite"
)

const (
	Name = "windows/winget"
)

type Configuration struct {
	DatabasePaths []string
}

func DefaultConfiguration() Configuration {
	userHome, err := os.UserHomeDir()
	if err != nil {
		username := os.Getenv("USERNAME")
		userHome = filepath.Join("C:", "Users", username)
	}
	
	return Configuration{
		DatabasePaths: []string{
			filepath.Join(userHome, "AppData", "Local", "Packages", "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe", "LocalState", "Microsoft.Winget.Source_8wekyb3d8bbwe", "installed.db"),
			filepath.Join(userHome, "AppData", "Local", "Packages", "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe", "LocalState", "StoreEdgeFD", "installed.db"),
			filepath.Join("C:", "ProgramData", "Microsoft", "Windows", "AppRepository", "StateRepository-Machine.srd"),
		},
	}
}

type Extractor struct {
	config Configuration
}

func New(config Configuration) standalone.Extractor {
	return &Extractor{
		config: config,
	}
}

func NewDefault() standalone.Extractor {
	return New(DefaultConfiguration())
}

func (e Extractor) Name() string { return Name }

func (e Extractor) Version() int { return 0 }

func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSWindows, RunningSystem: true}
}

type WingetPackage struct {
	ID       string
	Name     string
	Version  string
	Moniker  string
	Channel  string
	Tags     []string
	Commands []string
}

func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	var db *sql.DB
	var dbPath string
	var lastErr error

	for _, path := range e.config.DatabasePaths {
		if _, statErr := os.Stat(path); statErr != nil {
			continue
		}

		db, lastErr = sql.Open("sqlite", path)
		if lastErr != nil {
			continue
		}

		if err := e.validateDatabase(ctx, db); err != nil {
			db.Close()
			lastErr = err
			continue
		}

		dbPath = path
		break
	}

	if db == nil {
		if lastErr != nil {
			return inventory.Inventory{}, fmt.Errorf("failed to open any Winget database: %w", lastErr)
		}
		return inventory.Inventory{}, errors.New("no Winget database found")
	}
	defer db.Close()

	packages, err := e.extractPackages(ctx, db)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to extract packages from %s: %w", dbPath, err)
	}

	var extPackages []*extractor.Package
	for _, pkg := range packages {
		extPkg := &extractor.Package{
			Name:     pkg.ID,
			Version:  pkg.Version,
			PURLType: "winget",
			Metadata: &metadata.WingetPackage{
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

	return inventory.Inventory{Packages: extPackages}, nil
}

func (e *Extractor) validateDatabase(ctx context.Context, db *sql.DB) error {
	var tableName string
	err := db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name='manifest'").Scan(&tableName)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("database does not contain manifest table")
		}
		return fmt.Errorf("failed to query database schema: %w", err)
	}
	return nil
}

func (e *Extractor) extractPackages(ctx context.Context, db *sql.DB) ([]*WingetPackage, error) {
	query := `
	SELECT 
		i.id as package_id,
		n.name as package_name,
		v.version as package_version,
		m.moniker as package_moniker,
		c.channel as channel,
		GROUP_CONCAT(t.tag) as tags,
		GROUP_CONCAT(cmd.command) as commands
	FROM manifest man
	JOIN ids i ON man.id = i.rowid
	JOIN names n ON man.name = n.rowid  
	JOIN versions v ON man.version = v.rowid
	JOIN monikers m ON man.moniker = m.rowid
	JOIN channels c ON man.channel = c.rowid
	LEFT JOIN tags_map tm ON man.rowid = tm.manifest
	LEFT JOIN tags t ON tm.tag = t.rowid
	LEFT JOIN commands_map cm ON man.rowid = cm.manifest
	LEFT JOIN commands cmd ON cm.command = cmd.rowid
	GROUP BY man.rowid
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query packages: %w", err)
	}
	defer rows.Close()

	var packages []*WingetPackage
	for rows.Next() {
		var pkg WingetPackage
		var tagsStr, commandsStr sql.NullString

		err := rows.Scan(
			&pkg.ID,
			&pkg.Name,
			&pkg.Version,
			&pkg.Moniker,
			&pkg.Channel,
			&tagsStr,
			&commandsStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package row: %w", err)
		}

		if tagsStr.Valid && tagsStr.String != "" {
			pkg.Tags = strings.Split(tagsStr.String, ",")
		}
		if commandsStr.Valid && commandsStr.String != "" {
			pkg.Commands = strings.Split(commandsStr.String, ",")
		}

		packages = append(packages, &pkg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating package rows: %w", err)
	}

	return packages, nil
}