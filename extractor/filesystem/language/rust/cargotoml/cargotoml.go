package cargotoml

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type cargoTomlDependency struct {
	Version string
}

// UnmarshalTOML parses a dependency from a Cargo.toml file.
//
// Dependencies in Cargo.toml can be defined as simple strings (e.g., version)
// or as more complex objects (e.g., with version, path, etc.)
func (v *cargoTomlDependency) UnmarshalTOML(data any) error {
	getString := func(m map[string]any, key string) (string, bool) {
		v, ok := m[key]
		if !ok {
			return "", false
		}
		s, ok := v.(string)
		return s, ok
	}

	switch data := data.(type) {
	case string:
		v.Version = data
		return nil
	case map[string]any:
		if version, ok := getString(data, "version"); ok {
			v.Version = version
			return nil
		}
		if tag, ok := getString(data, "tag"); ok {
			v.Version = tag
			return nil
		}
		// no version or tag found; no error is returned as both fields are optional
		return nil
	default:
		return errors.New("invalid format for Cargo.toml dependency")
	}
}

type cargoTomlPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type cargoTomlFile struct {
	Package      cargoTomlPackage               `toml:"package"`
	Dependencies map[string]cargoTomlDependency `toml:"dependencies"`
}

// Extractor extracts crates.io packages from Cargo.toml files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "rust/Cargotoml" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches Cargo toml file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Cargo.toml"
}

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Extract extracts packages from Cargo.toml files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedTomlFile cargoTomlFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedTomlFile)
	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(parsedTomlFile.Dependencies)+1)

	packages = append(packages, &extractor.Inventory{
		Name:      parsedTomlFile.Package.Name,
		Version:   parsedTomlFile.Package.Version,
		Locations: []string{input.Path},
	})

	for name, dependency := range parsedTomlFile.Dependencies {
		packages = append(packages, &extractor.Inventory{
			Name:      name,
			Version:   dependency.Version,
			Locations: []string{input.Path},
		})
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeCargo,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Ecosystem returns the OSV ecosystem ('crates.io') of the software extracted by this extractor.
func (e Extractor) Ecosystem(_ *extractor.Inventory) string {
	return "crates.io"
}

var _ filesystem.Extractor = Extractor{}
