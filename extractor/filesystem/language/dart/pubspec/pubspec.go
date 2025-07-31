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

// Package pubspec extracts Dart pubspec.lock files.
package pubspec

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"gopkg.in/yaml.v3"
)

const (
	// Name is the unique name of this extractor.
	Name = "dart/pubspec"
)

type pubspecLockDescription struct {
	Ref string `yaml:"resolved-ref"`
}

var _ yaml.Unmarshaler = &pubspecLockDescription{}

// UnmarshalYAML is a custom unmarshalling function for pubspecLockDescription.
// We need this because descriptions can have two different formats.
func (pld *pubspecLockDescription) UnmarshalYAML(value *yaml.Node) error {
	// Duplicating the struct to decode nested fields as a
	// workaround for https://github.com/go-yaml/yaml/issues/1000
	var m struct {
		Ref string `yaml:"resolved-ref"`
	}
	if err := value.Decode(&m); err == nil {
		pld.Ref = m.Ref
		return nil
	}

	// If the above failed, the description is a single name string with no ref.
	return nil
}

type pubspecLockPackage struct {
	Description pubspecLockDescription `yaml:"description"`
	Version     string                 `yaml:"version"`
	Dependency  string                 `yaml:"dependency"`
}

type pubspecLockfile struct {
	Packages map[string]pubspecLockPackage `yaml:"packages,omitempty"`
}

// Extractor extracts Dart pubspec.lock files
type Extractor struct{}

// New returns a new instance of this Extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a pubspec.lock
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pubspec.lock"
}

// Extract extracts Dart packages from pubspec.lock files passed through the input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *pubspecLockfile
	if err := yaml.NewDecoder(input.Reader).Decode(&parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))

	for name, pkg := range parsedLockfile.Packages {
		pkgDetails := &extractor.Package{
			Name:      name,
			Version:   pkg.Version,
			PURLType:  purl.TypePub,
			Locations: []string{input.Path},
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: pkg.Description.Ref,
			},
			Metadata: osv.DepGroupMetadata{},
		}
		for _, str := range strings.Split(pkg.Dependency, " ") {
			if str == "dev" {
				pkgDetails.Metadata = osv.DepGroupMetadata{DepGroupVals: []string{"dev"}}
				break
			}
		}
		packages = append(packages, pkgDetails)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
