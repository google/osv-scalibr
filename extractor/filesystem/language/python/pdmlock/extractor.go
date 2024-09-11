// Package pdmlock extracts pdm.lock files.
package pdmlock

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/internal/pypipurl"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type pdmLockPackage struct {
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Groups   []string `toml:"groups"`
	Revision string   `toml:"revision"`
}

type pdmLockFile struct {
	Version  string           `toml:"lock-version"`
	Packages []pdmLockPackage `toml:"package"`
}

const pdmEcosystem = "PyPI"

// Extractor extracts python packages from pdm.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "python/pdmlock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches PDM lockfile patterns.
func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "pdm.lock"
}

// Extract extracts packages from pdm.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockFile *pdmLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockFile)
	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}
	packages := make([]*extractor.Inventory, 0, len(parsedLockFile.Packages))

	for _, pkg := range parsedLockFile.Packages {
		inventory := &extractor.Inventory{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Locations: []string{input.Path},
		}

		depGroups := []string{}

		var optional = true
		for _, gr := range pkg.Groups {
			if gr == "dev" {
				depGroups = append(depGroups, "dev")
				optional = false
			} else if gr == "default" {
				optional = false
			}
		}
		if optional {
			depGroups = append(depGroups, "optional")
		}

		inventory.Metadata = osv.DepGroupMetadata{
			DepGroupVals: depGroups,
		}

		if pkg.Revision != "" {
			inventory.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: pkg.Revision,
			}
		}

		packages = append(packages, inventory)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return pypipurl.MakePackageURL(i), nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns the OSV ecosystem ('PyPI') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return pdmEcosystem, nil
}

var _ filesystem.Extractor = Extractor{}
