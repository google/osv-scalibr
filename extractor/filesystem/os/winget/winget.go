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
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/winget/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	_ "modernc.org/sqlite"
)

const (
	Name = "os/winget"
)

type Extractor struct{}

func New() filesystem.Extractor {
	return &Extractor{}
}

func NewDefault() filesystem.Extractor {
	return New()
}

func (e Extractor) Name() string { return Name }

func (e Extractor) Version() int { return 0 }

func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSWindows}
}

func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	normalized := filepath.ToSlash(path)

	// Check if this is a Winget database file
	if strings.HasSuffix(normalized, "/installed.db") &&
		(strings.Contains(normalized, "/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe/") ||
			strings.Contains(normalized, "/StoreEdgeFD/")) {
		return true
	}

	// Check for system-wide repository database
	if strings.HasSuffix(normalized, "/StateRepository-Machine.srd") &&
		strings.Contains(normalized, "/AppRepository/") {
		return true
	}

	return false
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

func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	absPath, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("GetRealPath(%v): %w", input, err)
	}

	if input.Root == "" {
		// The file got copied to a temporary dir, remove it at the end.
		defer func() {
			dir := filepath.Dir(absPath)
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("Warning: failed to clean up temporary directory %s: %v\n", dir, err)
			}
		}()
	}

	db, err := sql.Open("sqlite", absPath)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to open Winget database %s: %w", absPath, err)
	}
	defer db.Close()

	if err := e.validateDatabase(ctx, db); err != nil {
		return inventory.Inventory{}, fmt.Errorf("invalid Winget database %s: %w", absPath, err)
	}

	packages, err := e.extractPackages(ctx, db)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to extract packages from %s: %w", absPath, err)
	}

	var extPackages []*extractor.Package
	for _, pkg := range packages {
		// Return if canceled or exceeding deadline
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		extPkg := &extractor.Package{
			Name:      pkg.ID,
			Version:   pkg.Version,
			PURLType:  purl.TypeWinget,
			Locations: []string{input.Path},
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
		// Return if canceled or exceeding deadline
		if err := ctx.Err(); err != nil {
			return packages, fmt.Errorf("winget extractor halted due to context error: %w", err)
		}

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
