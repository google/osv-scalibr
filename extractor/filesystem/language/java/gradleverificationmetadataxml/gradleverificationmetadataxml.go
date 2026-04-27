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

// Package gradleverificationmetadataxml extracts Gradle files.
package gradleverificationmetadataxml

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/gradleverificationmetadataxml"

	tagComponent = "component"
	attrGroup    = "group"
	attrName     = "name"
	attrVersion  = "version"
)

// pkgKey is a key for indexing packages by group, name, and version.
// This is used for faster lookup when matching packages to their line number locations in the file.
type pkgKey struct {
	group, name, version string
}

type gradleVerificationMetadataFile struct {
	Components []struct {
		Group   string `xml:"group,attr"`
		Name    string `xml:"name,attr"`
		Version string `xml:"version,attr"`
	} `xml:"components>component"`
}

// Extractor extracts Maven packages from Gradle verification metadata files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Gradle verification metadata lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return filepath.Base(filepath.Dir(path)) == "gradle" && filepath.Base(path) == "verification-metadata.xml"
}

// Extract extracts packages from verification-metadata.xml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read input: %w", err)
	}

	var parsedLockfile *gradleVerificationMetadataFile
	err = xml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Components))

	for _, component := range parsedLockfile.Components {
		packages = append(packages, &extractor.Package{
			Name:     component.Group + ":" + component.Name,
			Version:  component.Version,
			PURLType: purl.TypeMaven,
			Metadata: &javalockfile.Metadata{
				ArtifactID: component.Name,
				GroupID:    component.Group,
			},
			Location: extractor.PackageLocation{
				Descriptor: &location.Location{
					File: &location.File{
						Path:       input.Path,
						LineNumber: 0, // will be populated later in a "second pass"
					},
				},
			},
		})
	}

	// Populate the packages with line number information.
	//
	// We use a "two-pass" approach to identify the component line number that defines a package.
	// The initial decoding above unmarshals the XML into a Package struct, with no information about
	// the file line number where the struct was defined.
	// Populating the line numbers for these packages in a "second pass" is more maintainable and
	// simpler than unmarshalling the XML into a struct AND recording line numbers in a single pass.
	if err := e.populateLineNumbers(content, packages); err != nil {
		return inventory.Inventory{}, err
	}

	return inventory.Inventory{Packages: packages}, nil
}

// populateLineNumbers identifies the line number in the file where each extracted package was
// defined.
func (e Extractor) populateLineNumbers(content []byte, packages []*extractor.Package) error {
	// Use map to index packages by groupID, artifactID, and version.
	// Note that a valid file would not have duplicates of these keys.
	// However, if there are duplicates, we will only record package information for the first one
	// encountered.
	pkgMap := make(map[pkgKey][]*extractor.Package)
	for _, pkg := range packages {
		meta := pkg.Metadata.(*javalockfile.Metadata)
		key := pkgKey{group: meta.GroupID, name: meta.ArtifactID, version: pkg.Version}
		pkgMap[key] = append(pkgMap[key], pkg)
	}

	decoder := xml.NewDecoder(bytes.NewReader(content))
	lineNum := 1
	lastOffset := int64(0) // byte position
	for {
		t, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to decode tokens: %w", err)
		}
		offset := decoder.InputOffset() // new byte position

		// Update running line count based on the number of newlines characters between last offset and
		// current offset.
		lineNum += bytes.Count(content[lastOffset:offset], []byte{'\n'})
		lastOffset = offset

		switch element := t.(type) {
		case xml.StartElement:
			if element.Name.Local == tagComponent {
				key := pkgKey{
					group:   attr(element.Attr, attrGroup),
					name:    attr(element.Attr, attrName),
					version: attr(element.Attr, attrVersion),
				}

				pkgs, ok := pkgMap[key]
				if ok {
					for _, pkg := range pkgs {
						if pkg.Location.Descriptor.File.LineNumber == 0 {
							pkg.Location.Descriptor.File.LineNumber = lineNum
							break
						}
					}
				} else {
					log.Warnf("Could not identify line number for package with key %v", key)
				}
			}
		}
	}
	return nil
}

func attr(attrs []xml.Attr, name string) string {
	for _, attr := range attrs {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

var _ filesystem.Extractor = Extractor{}
