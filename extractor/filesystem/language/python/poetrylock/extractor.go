package poetrylock

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type poetryLockPackageSource struct {
	Type   string `toml:"type"`
	Commit string `toml:"resolved_reference"`
}

type poetryLockPackage struct {
	Name     string                  `toml:"name"`
	Version  string                  `toml:"version"`
	Optional bool                    `toml:"optional"`
	Source   poetryLockPackageSource `toml:"source"`
}

type poetryLockFile struct {
	Version  int                 `toml:"version"`
	Packages []poetryLockPackage `toml:"package"`
}

const poetryEcosystem = "PyPI"

// Extractor extracts python packages from poetry.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "python/poetrylock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches poetry lockfile patterns
func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "poetry.lock"
}

// Extract extracts packages from poetry.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *poetryLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		pkgDetails := &extractor.Inventory{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Locations: []string{input.Path},
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: lockPackage.Source.Commit,
			},
		}
		if lockPackage.Optional {
			pkgDetails.Metadata = osv.DepGroupMetadata{
				DepGroupVals: []string{"optional"},
			}
		} else {
			pkgDetails.Metadata = osv.DepGroupMetadata{
				DepGroupVals: []string{},
			}
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns the OSV ecosystem ('PyPI') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return poetryEcosystem, nil
}

var _ filesystem.Extractor = Extractor{}
