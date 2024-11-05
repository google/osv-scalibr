// Copyright 2024 Google LLC
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
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"gopkg.in/yaml.v3"
)

type pubspecLockDescription struct {
	Ref string `yaml:"resolved-ref"`
}

var _ yaml.Unmarshaler = &pubspecLockDescription{}

// UnmarshalYAML is a custom unmarshals function for pubspecLockDescription.
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

// Name of the extractor
func (e Extractor) Name() string { return "dart/pubspec" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a pubspec.lock
func (e Extractor) FileRequired(path string, _ func() (fs.FileInfo, error)) bool {
	return filepath.Base(path) == "pubspec.lock"
}

// Extract extracts Dart packages from pubspec.lock files passed through the input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *pubspecLockfile
	if err := yaml.NewDecoder(input.Reader).Decode(&parsedLockfile); err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(parsedLockfile.Packages))

	for name, pkg := range parsedLockfile.Packages {
		pkgDetails := &extractor.Inventory{
			Name:      name,
			Version:   pkg.Version,
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

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypePub,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string { return "Pub" }

var _ filesystem.Extractor = Extractor{}
